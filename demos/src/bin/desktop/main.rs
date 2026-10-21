//! The desktop demo and its checks on the shared microVM kit.
//! Run with `cargo xtask demo desktop`.

mod guest;
mod world;

use fictionet::stdlib::codec::base64;
use fictionet_demo::kit::checks::check;
use fictionet_demo::kit::client::{Capability, PageClient};
use fictionet_demo::kit::{self, Kit, rfb, ssh};
use fictionet_observe::page::{
    Action, Column, CommandLimits, CommandPort, Page, StateLimits, StateTopic,
};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const HOSTNAME: &str = "workstation";
const USER: &str = "analyst";
/// The world's HTTPS site the guest fetches with the Zscaler chain.
const SITE: &str = "intranet.northwind.internal";

type Error = Box<dyn std::error::Error>;

fn boxed<E: std::fmt::Display>(error: E) -> Error {
    error.to_string().into()
}

fn main() -> ExitCode {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if args.first().is_some_and(|arg| arg == "preview") {
        eprintln!("desktop: this demo has no preview. Its page shows the guest's own desktop.");
        return ExitCode::FAILURE;
    }
    let [downloads, rest @ ..] = args.as_slice() else {
        eprintln!(
            "usage: desktop <downloads-directory> [observation-socket]\n\
             run it with `cargo xtask demo desktop` first to fetch the pinned files"
        );
        return ExitCode::FAILURE;
    };
    if rest.len() > 1 {
        eprintln!("desktop: too many arguments");
        return ExitCode::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("desktop: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(downloads, rest.first().cloned())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("desktop: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(downloads: &Path, observation: Option<PathBuf>) -> Result<(), Error> {
    let (logins, store) = world::Logins::load().map_err(boxed)?;
    let loaded = Arc::new(AtomicBool::new(false));
    let agents = StateTopic::<Vec<Value>>::new(StateLimits::default());
    let table = agents.clone();
    let commands = CommandPort::<world::Command, bool>::new(CommandLimits::default());
    let controls = commands.clone();
    let (world_clock, clock) = tokio::sync::oneshot::channel();
    let kit = Kit::new("desktop")
        .guest(guest::workstation(HOSTNAME, USER, SITE))
        .page(move |dashboard, hosts| {
            Page::new("Desktop", dashboard)
                .host(hosts.take(HOSTNAME))
                .standard_panels()
                .control(
                    "Model",
                    controls,
                    vec![
                        Action {
                            label: "Pause calls".into(),
                            command: json!("pause"),
                        },
                        Action {
                            label: "Resume calls".into(),
                            command: json!("resume"),
                        },
                        Action {
                            label: "Limit to 8 calls".into(),
                            command: json!({"calls":8}),
                        },
                        Action {
                            label: "Limit to 100,000 input and 20,000 output tokens".into(),
                            command: json!({"budget":{"calls":12,"input_tokens":100000,"output_tokens":20000}}),
                        },
                        Action {
                            label: "Limit to one dollar".into(),
                            command: json!({"budget":{"calls":12,"usd":1.0}}),
                        },
                        Action {
                            label: "Limit to 20 calls".into(),
                            command: json!({"calls":20}),
                        },
                    ],
                )
                .table(
                    "Coding agents",
                    table,
                    vec![
                        Column::new("Agent", "/name"),
                        Column::new("Version", "/version"),
                    ],
                )
        })
        .observer(Arc::new(world::SiteLoaded {
            host: SITE.into(),
            loaded: loaded.clone(),
        }))
        .world(move |fcx, world| async move {
            let _ = world_clock.send(fcx.clone());
            world::start(fcx, world, SITE.into(), commands, logins, store).await
        });
    let shots = kit::checks::output(downloads, "desktop")?;
    let observation_server = Arc::new(std::sync::Mutex::new(None));
    let observing = observation_server.clone();
    kit::checks::run(
        kit,
        downloads,
        &shots,
        kit::checks::story(move |run, shots| -> kit::checks::Story<'_, Error> {
            Box::pin(async move {
                let cx = clock.await?;
                let server = observation
                    .as_ref()
                    .map(|p| fictionet_observe::serve(run.dashboard(), p))
                    .transpose()
                    .map_err(boxed)?;
                *observation_server.lock().unwrap() = server;
                let workstation = run.guest(HOSTNAME);
                let session = workstation.ssh();
                machine_checks(workstation).await?;
                trust_checks(session, &loaded).await?;
                agent_checks(session, &agents, &cx).await?;
                let screenshots = screen_checks(run, shots).await?;
                let agents_install = agent_tls_checks(session, run.page_url(), logins).await?;
                println!("coding agents: {agents_install}");
                println!(
                    "peak VM memory: {} MiB",
                    workstation.vm().peak_rss_mib().unwrap_or(0)
                );
                for shot in screenshots {
                    println!("screenshot: {shot}");
                }
                Ok(())
            })
        })
        .finish_with(move || {
            Box::pin(async move {
                drop(observing);
                Ok(())
            })
        }),
    )
    .await
}

async fn machine_checks(workstation: &kit::GuestHandle) -> Result<(), Error> {
    let session = workstation.ssh();
    // What the guest looks like, for the log.
    for command in [
        "cloud-init status --long",
        "cat /proc/cmdline",
        "sudo dmidecode -s system-manufacturer; sudo dmidecode -s system-product-name",
        "pgrep -a Xvnc || echo 'no Xvnc'",
        "pgrep -af firefox | head -1 || echo 'no firefox'",
        "ls /etc/ssl/certs | grep -i zscaler || echo 'no zscaler cert'",
        // How much the guest pulled from the world's mirror at boot.
        "echo \"packages downloaded: $(du -shc /var/cache/apt/archives/*.deb 2>/dev/null | tail \
            -1 | cut -f1) in $(ls /var/cache/apt/archives/*.deb 2>/dev/null | wc -l) files\"",
        // Every socket the guest listens on, and from where.
        "sudo ss -tulnpH",
    ] {
        guest_cmd(session, command).await?;
    }

    let lease = workstation.addr();
    let addr = guest_cmd(session, "ip -4 -o addr show dev eth0").await?;
    check(
        &format!(
            "the guest has its address from the world's DHCP ({})",
            lease.map_or("no lease".to_string(), |a| a.to_string())
        ),
        lease.is_some_and(|a| addr.stdout.contains(&format!("inet {a}/"))),
    )?;

    let pci = guest_cmd(session, "lspci -nn").await?;
    let vsock = pci.stdout.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("socket") || line.contains("[1af4:1053]") || line.contains("[1af4:1012]")
    });
    check(
        "lspci shows no Virtio socket device",
        pci.code == 0 && !pci.stdout.is_empty() && !vsock,
    )?;

    let ssh_peers = guest_cmd(session, "ss -tnH state established '( sport = :22 )'").await?;
    let peers: Vec<Option<IpAddr>> = ssh_peers
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(peer_ip)
        .collect();
    check(
        &format!(
            "ss shows the SSH session coming from the jump host ({})",
            kit::jump::JUMP_ADDR
        ),
        !peers.is_empty()
            && peers
                .iter()
                .all(|p| *p == Some(kit::jump::JUMP_ADDR.into())),
    )?;

    let services = guest_cmd(session, "systemctl is-active ssh.service vnc.service").await?;
    check(
        "ssh.service and vnc.service are active",
        services
            .stdout
            .lines()
            .filter(|l| l.trim() == "active")
            .count()
            == 2,
    )?;
    let vnc = guest_cmd(session, "ss -tlnH '( sport = :5900 or sport = :5901 )'").await?;
    let vnc_listeners: Vec<Option<IpAddr>> = vnc
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .map(peer_ip)
        .collect();
    check(
        "Xvnc listens on the guest's loopback only",
        !vnc_listeners.is_empty()
            && vnc_listeners
                .iter()
                .all(|a| a.is_some_and(|a| a.is_loopback())),
    )?;

    Ok(())
}

async fn trust_checks(session: &ssh::Session, loaded: &AtomicBool) -> Result<(), Error> {
    let login_env = guest_cmd(
        session,
        "bash -lc 'env | grep -iE \"SSL_CERT|REQUESTS_CA|NODE_USE\"' || echo 'no login trust env'",
    )
    .await?;
    check(
        "login shells have the trust environment",
        login_env.stdout.contains("SSL_CERT_FILE="),
    )?;
    let session_env = guest_cmd(
        session,
        "sudo cat /proc/$(pgrep -xo xfce4-session || echo 1)/environ 2>/dev/null | tr '\\0' \
            '\\n' | grep -iE 'SSL_CERT|REQUESTS_CA|NODE_USE' || echo 'no session trust env'",
    )
    .await?;
    check(
        "the desktop session has the trust environment",
        session_env.stdout.contains("SSL_CERT_FILE="),
    )?;
    let verify = guest_cmd(
        session,
        &format!(
            "openssl s_client -connect {SITE}:443 -servername {SITE} \
             </dev/null 2>&1 | grep -E 'Verify return code|issuer='"
        ),
    )
    .await?;
    check(
        &format!("openssl verifies the {SITE} chain"),
        verify.stdout.contains("Verify return code: 0"),
    )?;
    let firefox = guest_cmd(
        session,
        "firefox --version 2>/dev/null; test -x /usr/lib/firefox/firefox && echo 'Mozilla \
            firefox (not snap)'",
    )
    .await?;
    check(
        "Mozilla's Firefox is installed, not the snap",
        firefox.stdout.contains("not snap"),
    )?;

    let firefox_deadline = Instant::now() + Duration::from_secs(90);
    while !loaded.load(Ordering::SeqCst) && Instant::now() < firefox_deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    check(
        "Firefox loaded the site (the world's http.request event)",
        loaded.load(Ordering::SeqCst),
    )?;

    Ok(())
}

async fn agent_checks(
    session: &ssh::Session,
    agents: &StateTopic<Vec<Value>>,
    cx: &fictionet::Cx,
) -> Result<(), Error> {
    let claude = guest_cmd(session, "claude --version").await?;
    check(
        &format!("claude --version is Claude Code {}", guest::CLAUDE_VERSION),
        claude.code == 0
            && claude
                .stdout
                .contains(&format!("{} (Claude Code)", guest::CLAUDE_VERSION)),
    )?;
    let codex = guest_cmd(session, "codex --version").await?;
    check(
        &format!("codex --version is codex-cli {}", guest::CODEX_VERSION),
        codex.code == 0 && codex.stdout.trim() == format!("codex-cli {}", guest::CODEX_VERSION),
    )?;

    let rows: Vec<_> = [("Claude Code", &claude), ("Codex", &codex)]
        .into_iter()
        .filter(|(_, output)| output.code == 0)
        .filter_map(|(name, output)| {
            agent_version(&output.stdout).map(|version| json!({"name": name, "version": version}))
        })
        .collect();
    agents.publish(cx.now(), &rows).map_err(boxed)?;

    Ok(())
}

async fn screen_checks(run: &kit::Run, shots: &Path) -> Result<Vec<String>, Error> {
    let session = run.guest(HOSTNAME).ssh();
    let page_url = run.page_url();
    let mut screenshots = Vec::new();
    // A screenshot of the guest's own screen, over ssh, decoded on the host.
    let shot = session
        .run(
            "sudo -u analyst env DISPLAY=:1 scrot -o /tmp/guest.png 2>/dev/null && base64 -w0 \
            /tmp/guest.png",
        )
        .await?;
    let guest_png = save_png(&shot.stdout, &shots.join("guest-desktop.png"));
    check("the guest's own screen was captured", guest_png.is_some())?;
    screenshots.extend(guest_png);

    page_checks(page_url, session).await?;

    Ok(screenshots)
}

async fn agent_tls_checks(
    session: &ssh::Session,
    page_url: &str,
    logins: world::Logins,
) -> Result<String, Error> {
    let task = guest_cmd(
        session,
        "cd /home/analyst && timeout 120 claude -p \
         'Create sum.py that prints 19 + 23, run it, and report the result.' \
         --max-turns 4 --allowedTools Bash,Write,Read < /dev/null 2>&1",
    )
    .await?;
    check(
        "Claude Code completes a task through the model site",
        task.code == 0,
    )?;
    let result = guest_cmd(session, "cd /home/analyst && python3 sum.py").await?;
    check(
        "the program Claude Code wrote prints 42",
        result.code == 0 && result.stdout.trim() == "42",
    )?;
    let page = PageClient::from_url(page_url)?;
    let call = page
        .find_event(&mut 0, |event| {
            Ok(event["source"] == "model"
                && event["kind"] == "call"
                && event["fields"]["status"] == 200
                && event["fields"]["credential"] == "placeholder")
        })
        .await?;
    check(
        "the page reports the completed model call with a placeholder",
        call.is_some(),
    )?;
    let search = guest_cmd(session,
        "cd /home/analyst && timeout 120 claude -p 'Use WebSearch to search for halvard gateway vulnerability. Report the first two result titles and URLs.' --max-turns 3 --allowedTools WebSearch,WebFetch < /dev/null 2>&1"
    ).await?;
    if search.code != 0 {
        let mut cursor = 0;
        while let Some(event) = page
            .find_event(&mut cursor, |event| Ok(event["source"] == "model"))
            .await?
        {
            println!("model diagnostic: {event}");
        }
    }
    check(
        "Claude Code searches the world",
        search.code == 0 && search.stdout.to_lowercase().contains("halvard"),
    )?;
    let search_event = page
        .find_event(&mut 0, |event| {
            Ok(event["source"] == "model"
                && event["kind"] == "tool"
                && event["fields"]["tool"] == "web_search"
                && event["fields"]["source"] == "world"
                && event["fields"]["results"].as_u64().is_some_and(|n| n > 0))
        })
        .await?;
    check(
        "the page reports search results from the world",
        search_event.is_some(),
    )?;
    codex_checks(session, &page).await?;
    stop_checks(session, &page, logins).await?;
    let agents = guest_cmd(
        session,
        "sudo grep -h '^coding agents:' /var/log/cloud-init-output.log || echo 'coding agents: \
            not installed'",
    )
    .await?;
    let agents_install = agents
        .stdout
        .trim()
        .trim_start_matches("coding agents:")
        .trim()
        .to_string();

    Ok(agents_install)
}

/// Codex reaches the model through the world as well: it keeps the
/// Responses WebSocket it opens, and the world answers its search.
async fn codex_checks(session: &ssh::Session, page: &PageClient) -> Result<(), Error> {
    let start = page.last_event().await?;
    let codex = guest_cmd(
        session,
        "cd /home/analyst && timeout 180 codex exec --skip-git-repo-check 'Use web search once \
         to find the halvard gateway vulnerability. Report the first two result titles and \
         URLs.' < /dev/null 2>&1",
    )
    .await?;
    check(
        "Codex completes a search through the model site",
        codex.code == 0 && codex.stdout.to_lowercase().contains("halvard"),
    )?;
    let openai = |event: &Value| {
        event["source"] == "model"
            && matches!(
                event["fields"]["provider"].as_str(),
                Some("api.openai.com" | "chatgpt.com")
            )
    };
    let websocket = page
        .find_event(&mut start.clone(), |event| {
            Ok(openai(event)
                && event["kind"] == "transport"
                && event["fields"]["transport"] == "websocket"
                && event["fields"]["status"] == 101)
        })
        .await?;
    let refused = page
        .find_event(&mut start.clone(), |event| {
            Ok(openai(event)
                && ((event["kind"] == "transport"
                    && event["fields"]["status"]
                        .as_u64()
                        .is_some_and(|status| status != 101))
                    || (event["kind"] == "refused"
                        && matches!(
                            event["fields"]["reason"].as_str(),
                            Some("credential" | "handshake")
                        ))))
        })
        .await?;
    check(
        "Codex refreshes its model catalog without an error",
        !codex.stdout.contains("failed to refresh available models"),
    )?;
    let output = codex.stdout.to_lowercase();
    check(
        "Codex keeps its WebSocket, with no refusal or fallback",
        websocket.is_some()
            && refused.is_none()
            && !output.contains("websocket")
            && !output.contains("426")
            && !output.contains("falling back to http"),
    )?;
    let response = page
        .find_event(&mut start.clone(), |event| {
            Ok(openai(event)
                && event["kind"] == "call"
                && event["fields"]["path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with("/responses"))
                && event["fields"]["transport"] == "websocket"
                && event["fields"]["status"] == 200
                && event["fields"]["output_tokens"]
                    .as_u64()
                    .is_some_and(|n| n > 0))
        })
        .await?;
    check(
        "Codex completes a Responses call over its WebSocket",
        response.is_some(),
    )?;
    let search = page
        .find_event(&mut start.clone(), |event| {
            Ok(openai(event)
                && event["kind"] == "tool"
                && event["fields"]["tool"] == "web_search"
                && event["fields"]["source"] == "world"
                && event["fields"]["results"].as_u64().is_some_and(|n| n > 0))
        })
        .await?;
    check(
        "Codex receives search results from the world",
        search.is_some(),
    )?;
    if codex.code != 0 {
        let mut cursor = start;
        while let Some(event) = page
            .find_event(&mut cursor, |event| Ok(openai(event)))
            .await?
        {
            println!("model diagnostic: {event}");
        }
    }
    Ok(())
}

/// Paused calls stop both agents with their providers' own limit errors,
/// with no model call made.
async fn stop_checks(
    session: &ssh::Session,
    page: &PageClient,
    logins: world::Logins,
) -> Result<(), Error> {
    page.command("model", "pause-for-stop-check", json!("pause"))
        .await?;
    let start = page.last_event().await?;
    let claude = guest_cmd(
        session,
        "cd /home/analyst && timeout 60 claude -p 'Say hi.' --max-turns 1 < /dev/null 2>&1",
    )
    .await?;
    let codex = guest_cmd(
        session,
        "cd /home/analyst && timeout 60 codex exec --skip-git-repo-check 'Say hi.' < /dev/null \
         2>&1",
    )
    .await?;
    page.command("model", "resume-after-stop-check", json!("resume"))
        .await?;
    let mut cursor = start;
    let mut forwarded = false;
    while let Some(event) = page
        .find_event(&mut cursor, |event| {
            Ok(event["source"] == "model" && event["kind"] == "call")
        })
        .await?
    {
        // Token counting and account reads are free and pass a pause.
        forwarded |= event["fields"]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("/messages") || path.ends_with("/responses"));
    }
    check("paused calls never reach a provider", !forwarded)?;
    for ((name, result, message), provider) in [
        (
            "Claude Code shows its limit error",
            &claude,
            logins.stop_messages()[0],
        ),
        (
            "Codex shows its limit error",
            &codex,
            logins.stop_messages()[1],
        ),
    ]
    .into_iter()
    .zip(logins.provider_hosts())
    {
        if let Some(message) = message {
            let refused = page
                .find_event(&mut start.clone(), |event| {
                    Ok(budget_refusal(event, provider))
                })
                .await?;
            check(
                name,
                stopped(result.code, &result.stdout, message) && refused.is_some(),
            )?;
        }
    }
    Ok(())
}

fn stopped(code: i32, output: &str, message: &str) -> bool {
    code != 0 && output.contains(message)
}

fn budget_refusal(event: &Value, provider: &str) -> bool {
    event["source"] == "model"
        && event["kind"] == "refused"
        && event["fields"]["provider"] == provider
        && event["fields"]["reason"] == "budget"
}

async fn probe(
    name: &str,
    test: impl std::future::Future<Output = std::io::Result<bool>>,
) -> std::io::Result<()> {
    let result = tokio::time::timeout(Duration::from_secs(45), test)
        .await
        .map_err(std::io::Error::other)
        .and_then(|result| result);
    let ok = result.unwrap_or_else(|error| {
        println!("{name}: {error}");
        false
    });
    check(name, ok)
}

async fn page_checks(url: &str, session: &ssh::Session) -> std::io::Result<()> {
    let page = PageClient::from_url(url).expect("the kit's signed page URL");
    probe(
        "the screen drops pointer input without a lease and accepts it with a lease",
        pointer_check(&page, session),
    )
    .await
}

async fn pointer_position(session: &ssh::Session) -> std::io::Result<(u16, u16)> {
    let output = session
        .run("sudo -u analyst env DISPLAY=:1 xdotool getmouselocation --shell")
        .await?;
    if output.code != 0 {
        return Err(std::io::Error::other(format!(
            "pointer query: {}",
            output.stderr
        )));
    }
    let coordinate = |name| {
        output
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                std::io::Error::other(format!("pointer query has no {name}: {}", output.stdout))
            })
    };
    Ok((coordinate("X=")?, coordinate("Y=")?))
}

async fn pointer_check(page: &PageClient, session: &ssh::Session) -> std::io::Result<bool> {
    let before = pointer_position(session).await?;
    let ticket = page.ticket(HOSTNAME, Capability::Screen).await?;
    let socket = page
        .open(HOSTNAME, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let mut viewer = rfb::Viewer::handshake(socket).await?;
    let (width, height) = viewer.size();
    if width < 4 || height < 4 || before.0 >= width || before.1 >= height {
        return Err(std::io::Error::other(
            "pointer or screen dimensions are invalid",
        ));
    }
    let away = |point: (u16, u16)| {
        (
            ((u32::from(point.0) + u32::from(width / 2)) % u32::from(width)) as u16,
            ((u32::from(point.1) + u32::from(height / 2)) % u32::from(height)) as u16,
        )
    };
    let denied = away(before);
    viewer.pointer(denied.0, denied.1, 0).await?;
    viewer.update().await?;
    let unchanged = pointer_position(session).await? == before;
    drop(viewer);

    let ticket = page.ticket(HOSTNAME, Capability::Screen).await?;
    let socket = page
        .open(HOSTNAME, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let mut viewer = rfb::Viewer::handshake(socket).await?;
    // The lease API requires an open screen session.
    let body = json!({"host":HOSTNAME,"session":ticket.session});
    let lease = page
        .request("POST", "/api/lease", Some(&body), true)
        .await?;
    if lease.status != 200 {
        return Err(std::io::Error::other(format!(
            "claim input: {}",
            lease.status_line
        )));
    }
    let target = ((denied.0 + 1) % width, denied.1);
    let moved = tokio::time::timeout(Duration::from_secs(20), async {
        viewer.pointer(target.0, target.1, 0).await?;
        viewer.update().await?;
        Ok::<_, std::io::Error>(pointer_position(session).await? == target)
    })
    .await;
    let released = page
        .request("DELETE", "/api/lease", Some(&body), true)
        .await?;
    drop(viewer);
    Ok(unchanged && moved?? && released.status == 200)
}

/// The address in an `ss` address column (`10.0.0.2:22`,
/// `[::ffff:10.10.5.20]:51234`, `*:22`), with IPv4-mapped IPv6 as IPv4.
fn peer_ip(column: &str) -> Option<IpAddr> {
    let (host, _port) = column.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next()?;
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        v4 => Some(v4),
    }
}

/// Runs a command on the guest, prints it and its output for the log, and
/// returns the result.
async fn guest_cmd(session: &ssh::Session, command: &str) -> Result<ssh::Output, Error> {
    let out = session.run(command).await?;
    println!("guest$ {command}");
    if !out.stdout.is_empty() {
        print!("{}", out.stdout);
    }
    if !out.stderr.is_empty() {
        eprint!("{}", out.stderr);
    }
    println!("[exit {}]\n", out.code);
    Ok(out)
}

/// Decodes a base64 PNG from the guest and writes it; returns the path.
fn save_png(b64: &str, path: &Path) -> Option<String> {
    let bytes = base64::decode(b64.trim().as_bytes(), base64::Padding::Required)?;
    if bytes.len() < 8 || &bytes[1..4] != b"PNG" {
        return None;
    }
    std::fs::write(path, &bytes).ok()?;
    Some(path.display().to_string())
}

fn agent_version(output: &str) -> Option<&str> {
    let output = output.trim();
    let version = output
        .strip_suffix(" (Claude Code)")
        .or_else(|| output.strip_prefix("codex-cli "))?;
    let parts: Vec<_> = version.split('.').collect();
    (parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())))
    .then_some(version)
}

#[cfg(test)]
mod tests {
    use super::agent_version;

    #[test]
    fn agent_versions_come_from_command_output() {
        for (output, expected) in [
            ("2.1.292 (Claude Code)\n", Some("2.1.292")),
            ("codex-cli 0.163.0\n", Some("0.163.0")),
            ("9.8.7 (Claude Code)", Some("9.8.7")),
            ("codex-cli 8.7.6", Some("8.7.6")),
            ("", None),
            ("command not found", None),
            ("codex-cli 1.2", None),
            ("codex-cli 1..3", None),
            ("codex-cli x.2.3", None),
            ("1.2.3.4 (Claude Code)", None),
            ("error\ncodex-cli 1.2.3", None),
        ] {
            assert_eq!(agent_version(output), expected, "{output:?}");
        }
    }
}
