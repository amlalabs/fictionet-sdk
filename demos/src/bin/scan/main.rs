//! Two Ubuntu guests inventory an office through the shared kit.
mod guests;
mod nmap;
mod story;
mod world;

use fictionet_demo::kit::{
    Kit,
    client::{Capability, PageClient},
};
use fictionet_observe::page::Page;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

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
    let kit = Kit::new("scan")
        .guest(guests::workstation())
        .guest(guests::server())
        .page(|dashboard, hosts| {
            Page::new("Scan", dashboard)
                .host(hosts.take(guests::WORKSTATION).pinned())
                .host(hosts.take(guests::SERVER).pinned())
                .standard_panels()
        })
        .world(move |cx, world| async move {
            let ports = world::start(&cx, world, cutoff)?;
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
        let cloud_init = Duration::from_secs(300);
        let (station, server) = tokio::join!(
            run.guest(guests::WORKSTATION).wait_cloud_init(cloud_init),
            run.guest(guests::SERVER).wait_cloud_init(cloud_init)
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
        let story = story::run(&run, &ports, &shots).await?;
        tokio::time::timeout(Duration::from_secs(45), page_checks(run.page_url())).await??;
        run.screenshots(
            guests::WORKSTATION,
            &shots.join("viewer-scan.png"),
            &shots.join("page-scan.png"),
        )
        .await?;
        Ok::<_, Error>((boot, story))
    }
    .await;
    if let Err(error) = &result {
        eprintln!("gate failed: {error}");
        for guest in run.guests() {
            eprint!("{}", guest.diagnostics().await);
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
    let description = client.get_json("/api/page").await?;
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
    socket
        .read_until(format!("name:{}:end", guests::SERVER).as_bytes(), 64 << 10)
        .await?;
    println!("[pass] page terminal hostname: {}", guests::SERVER);
    Ok(())
}
