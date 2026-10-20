//! Two Ubuntu guests inventory an office through the shared kit. A scripted
//! agent runs three nmap steps in the workstation's terminal; the office
//! server is a second VM among four simulated machines. The page shows both
//! VMs and the Office, Ports and Services panels; the gate checks nmap's
//! reports, the world's port map and the page's own API.
mod checks;
#[cfg(test)]
mod client;
mod guests;
mod nmap;
mod page;
mod script;
mod story;
mod world;

use fictionet_demo::kit::{
    self, Kit,
    client::{Capability, PageClient},
    rfb, shot,
};
use fictionet_observe::page::Page;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Error = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [downloads] = args.as_slice() else {
        eprintln!("usage: scan <downloads-directory>; run cargo xtask demo scan to fetch assets");
        return ExitCode::FAILURE;
    };
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| -> Error { e.into() })
        .and_then(|rt| rt.block_on(gate(downloads)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scan: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn gate(downloads: &Path) -> Result<(), Error> {
    let total = Instant::now();
    let closed = Arc::new(AtomicBool::new(false));
    let cutoff = closed.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    let topics = page::Topics::new();
    let progress = page::Progress::new();
    let published = (topics.clone(), progress.clone());
    let kit = Kit::new("scan")
        .guest(guests::workstation())
        .guest(guests::server())
        .page(move |dashboard, hosts| {
            topics.compose(
                Page::new(page::TITLE, dashboard)
                    .host(hosts.take(guests::WORKSTATION).pinned())
                    .host(hosts.take(guests::SERVER).pinned()),
            )
        })
        .world(move |cx, world| async move {
            let ports = world::start(&cx, world, cutoff)?;
            let (topics, progress) = published;
            page::publish(&cx, ports.clone(), topics, progress);
            let _ = send.send(ports);
            Ok(())
        });
    let shots = downloads.join("shots");
    std::fs::create_dir_all(&shots)?;
    let run = kit.boot(downloads).await?;
    let pids: Vec<_> = run.guests().iter().filter_map(|g| g.vm().pid()).collect();
    let dir = run.path().to_owned();
    for guest in run.guests() {
        println!(
            "{} boot to SSH-ready: {} ms",
            guest.name(),
            guest.ssh_ready().as_millis()
        );
    }
    let result = async {
        let ports = receive.await?;
        let (station, server) = tokio::join!(
            cloud_init(&run, guests::WORKSTATION),
            cloud_init(&run, guests::SERVER)
        );
        let station = station?;
        let server = server?;
        println!(
            "{} cloud-init done: {} ms",
            guests::WORKSTATION,
            station.as_millis()
        );
        println!(
            "{} cloud-init done: {} ms",
            guests::SERVER,
            server.as_millis()
        );
        closed.store(true, Ordering::SeqCst);
        println!("apt mirror closed: subsequent HTTP requests receive 403");
        run.guest(guests::WORKSTATION)
            .wait_desktop(Duration::from_secs(60))
            .await?;
        let boot = run.boot_started().elapsed();
        let story = story::run(&run, &ports, &shots, &progress).await?;
        tokio::time::timeout(Duration::from_secs(45), page_checks(run.page_url())).await??;
        let capture = tokio::time::timeout(
            Duration::from_secs(30),
            rfb::capture_page(
                run.page_url(),
                guests::WORKSTATION,
                &shots.join("viewer-scan.png"),
            ),
        )
        .await??;
        if capture.colors < 16 {
            return Err("scanner framebuffer has fewer than 16 colors".into());
        }
        println!(
            "RFB screenshot: {} ({}x{}, {} colors)",
            capture.png.display(),
            capture.width,
            capture.height,
            capture.colors
        );
        let url = run.page_url().to_owned();
        let out = shots.join("page-scan.png");
        let screenshot = tokio::task::spawn_blocking(move || {
            shot::capture(
                &url,
                &out,
                &shot::desktop_painted(guests::WORKSTATION),
                Duration::from_secs(60),
            )
        })
        .await??;
        println!("Chromium screenshot: {screenshot}");
        Ok::<_, Error>((boot, story))
    }
    .await;
    if let Err(error) = &result {
        eprintln!("gate failed: {error}");
        for guest in run.guests() {
            eprintln!(
                "{} console tail:\n{}",
                guest.name(),
                guest.vm().console_tail()
            );
        }
    }
    let stop = run.shutdown().await;
    let clean = !dir.exists()
        && pids
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists());
    if let Err(error) = stop {
        return Err(format!("shutdown failed: {error}; gate result: {result:?}").into());
    }
    if !clean {
        return Err(format!(
            "shutdown left a VM process or run directory; gate result: {result:?}"
        )
        .into());
    }
    println!("[pass] both VMs stopped; no VM processes or run directory remain");
    let (boot, story) = result?;
    println!("boot time: {} ms", boot.as_millis());
    println!("story time: {} ms", story.as_millis());
    println!("whole run: {} ms", total.elapsed().as_millis());
    println!("every required check passed");
    Ok(())
}

async fn cloud_init(run: &kit::Run, name: &str) -> Result<Duration, Error> {
    let output = tokio::time::timeout(
        Duration::from_secs(300),
        run.guest(name)
            .ssh()
            .run_bounded("sudo cloud-init status --wait --long", 64 << 10),
    )
    .await??;
    if output.code != 0 {
        return Err(format!(
            "{name}: cloud-init exit {}\n{}\n{}",
            output.code, output.stdout, output.stderr
        )
        .into());
    }
    Ok(run.boot_started().elapsed())
}

async fn page_checks(url: &str) -> Result<(), Error> {
    let client = PageClient::from_url(url)?;
    if client
        .request("GET", "/api/page", None, false)
        .await?
        .status
        != 401
    {
        return Err("page accepted an API call without the bearer".into());
    }
    client.bootstrap().await?;
    let page = client.request("GET", "/api/page", None, true).await?;
    if page.status != 200 {
        return Err("authenticated page API failed".into());
    }
    let description: serde_json::Value = serde_json::from_slice(&page.body)?;
    let hosts = description["hosts"].as_array().ok_or("page has no hosts")?;
    if hosts.len() != 2 || hosts.iter().any(|h| h["pinned"] != true) {
        return Err("page must pin both guests".into());
    }
    for (host, capability) in [
        (guests::WORKSTATION, Capability::Screen),
        (guests::SERVER, Capability::Terminal),
    ] {
        let refused = client
            .open(host, capability, None)
            .await
            .err()
            .ok_or("page accepted an upgrade without a ticket")?;
        if !refused.to_string().starts_with("HTTP/1.1 401 ") {
            return Err(format!("upgrade was not refused for authentication: {refused}").into());
        }
    }
    println!("[pass] page bearer and console ticket checks");
    let ticket = client.ticket(guests::SERVER, Capability::Terminal).await?;
    let mut socket = client
        .open(guests::SERVER, Capability::Terminal, Some(&ticket.ticket))
        .await?;
    socket
        .write_all(b"printf 'name:%s:end\\n' \"$(hostname)\"\r")
        .await?;
    let expected = format!("name:{}:end", guests::SERVER);
    let mut output = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            return Err("server terminal closed before returning hostname".into());
        }
        output.extend_from_slice(&chunk[..n]);
        if output
            .windows(expected.len())
            .any(|w| w == expected.as_bytes())
        {
            break;
        }
        let keep = output.len().saturating_sub(expected.len() - 1);
        output.drain(..keep);
    }
    println!("[pass] page terminal hostname: {}", guests::SERVER);
    // The world task publishes at most every 250 ms, so the last story step
    // can reach the page a moment after the story ends.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (topics, moment) = checks::read(&client).await?;
        match checks::check(&topics, &moment) {
            Ok(summary) => {
                println!("[pass] page topics: {summary}");
                return Ok(());
            }
            Err(error) if Instant::now() > deadline => {
                return Err(format!("page topics: {error}").into());
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}
