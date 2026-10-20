//! The scan page without VMs, to design against. The scan world runs in a
//! real-time run with an in-world scanner that sends the story's probes, and
//! a stand-in for the server VM answers with the banners the real server sent
//! in a KVM run. The page shows nmap's reports recorded in that run, and the
//! two hosts with status only and no console.
//!
//! Run `cargo run -p fictionet-demo --example scan_page`. It prints the page
//! URL and runs until Enter or the end of its input. `--bound` keeps probing
//! new ports after the story until the port map is full. `--no-os-match ADDR`
//! removes nmap's OS matches for one host from the recorded report, which is
//! what nmap reports when it makes no match.

mod client;
mod nmap;
mod page;
mod script;

use fictionet::{RunOptions, Seed};
use fictionet_observe::page::{Host, HostState, HostStatus, Page, StateLimits, StateTopic};
use fictionet_observe::{DashboardObserver, DashboardOptions};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// The demo's guest names, as its page shows them.
const WORKSTATION: &str = "workstation";
const SERVER: &str = "office";
/// nmap's reports for the three steps, from a KVM run of the demo.
const RECORDED: [&str; 3] = [
    include_str!("data/discovery.xml"),
    include_str!("data/services.xml"),
    include_str!("data/os.xml"),
];

struct Options {
    bound: bool,
    no_match: Option<Ipv4Addr>,
}

fn options() -> Result<Options, Error> {
    let mut options = Options {
        bound: false,
        no_match: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bound" => options.bound = true,
            "--no-os-match" => {
                let addr = args.next().ok_or("--no-os-match needs an address")?;
                options.no_match = Some(addr.parse()?);
            }
            _ => {
                return Err(
                    format!("unknown argument {arg}; use --bound or --no-os-match ADDR").into(),
                );
            }
        }
    }
    Ok(options)
}

/// nmap's recorded report for a step, without OS matches for one host when asked.
fn recorded(index: usize, no_match: Option<Ipv4Addr>) -> fictionet::Result<page::StepReport> {
    let mut report = nmap::parse(RECORDED[index]).map_err(fictionet::Error::msg)?;
    for host in &mut report.hosts {
        if host.ipv4() == no_match
            && let Some(os) = &mut host.os
        {
            os.matches.clear();
        }
    }
    Ok(page::StepReport::new(script::STEPS[index].title, &report))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options = options()?;
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let topics = page::Topics::new();
    let progress = page::Progress::new();
    let statuses = [(); 2].map(|()| StateTopic::<HostStatus>::new(StateLimits::default()));
    let server = topics
        .compose(
            Page::new(format!("{} · no VMs", page::TITLE), dashboard.handle())
                .host(
                    Host::new(WORKSTATION)
                        .sandbox(scan_world::SCANNER)
                        .status(statuses[0].clone())
                        .pinned(),
                )
                .host(
                    Host::new(SERVER)
                        .sandbox(scan_world::SERVER)
                        .status(statuses[1].clone())
                        .pinned(),
                ),
        )
        .bind_loopback(0)
        .await?;
    println!("{}", server.url());
    eprintln!(
        "No VM runs. An in-world scanner sends the story's probes; nmap's reports are recorded. Press Enter to stop."
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            RunOptions::new(Seed::from_u64(7)).observer(dashboard.observer()),
            move |cx| async move {
                // Enter stops the run, during the story too.
                cx.spawn(move |cx| async move {
                    while !stopping.load(Ordering::SeqCst) {
                        cx.sleep(Duration::from_millis(200)).await?;
                    }
                    cx.cancel();
                    Ok(())
                });
                let (attacher, attachments) = fictionet::attachments();
                let ports = scan_world::start(&cx, scan_world::office(), attachments)?;
                page::publish(&cx, ports.clone(), topics, progress.clone());
                let status = |topic: &StateTopic<HostStatus>, state, addr: Option<&str>| {
                    topic.publish(
                        cx.now(),
                        &HostStatus {
                            state,
                            addresses: addr.into_iter().map(Into::into).collect(),
                            screen: false,
                            terminal: false,
                        },
                    )
                };
                // nmap exited with each step's expected status in the recorded run.
                let finish = |index: usize| -> fictionet::Result {
                    let report = recorded(index, options.no_match)?;
                    let exit = script::STEPS[index].expected_exit;
                    progress.finish(index, Some(exit), Some(report), true);
                    Ok(())
                };
                status(&statuses[0], HostState::Booting, None)?;
                status(&statuses[1], HostState::Booting, None)?;
                client::serve_server(&cx, attacher.attach(scan_world::SERVER)?);
                let mut scanner =
                    client::Scanner::attach(&cx, attacher.attach(scan_world::SCANNER)?);
                cx.sleep(Duration::from_secs(2)).await?;
                status(&statuses[0], HostState::NetworkUp, Some("10.0.9.2"))?;
                status(&statuses[1], HostState::NetworkUp, Some("10.0.0.50"))?;
                cx.sleep(Duration::from_secs(3)).await?;

                progress.start(0);
                let up = scanner.sweep(&cx, Duration::from_millis(25)).await?;
                finish(0)?;
                cx.sleep(Duration::from_secs(2)).await?;

                progress.start(1);
                // nmap's --max-rate 300: one probe every 3.3 ms.
                let open = scanner
                    .scan(&cx, &up, 1..=1024, Duration::from_micros(3_333))
                    .await?;
                scanner.banners(&cx, &open).await?;
                finish(1)?;
                cx.sleep(Duration::from_secs(1)).await?;

                // The fixture sends no OS probes; it shows nmap's recorded guesses.
                progress.start(2);
                cx.sleep(Duration::from_secs(4)).await?;
                finish(2)?;

                if options.bound {
                    let rows = ports.snapshot().rows.len();
                    let past = u16::try_from(scan_world::ports::MAX_ROWS - rows + 64)
                        .map_err(fictionet::Error::msg)?;
                    let target = [Ipv4Addr::new(10, 0, 0, 10)];
                    scanner
                        .scan(&cx, &target, 1025..=1024 + past, Duration::ZERO)
                        .await?;
                    let map = ports.snapshot();
                    eprintln!(
                        "port map: {} rows, {} untracked probes",
                        map.rows.len(),
                        map.untracked
                    );
                }
                eprintln!("The story is done. Press Enter to stop.");
                cx.cancelled().await;
                Ok(())
            },
        ))
    });
    tokio::task::spawn_blocking(|| std::io::stdin().read_line(&mut String::new())).await??;
    stop.store(true, Ordering::SeqCst);
    match world.join() {
        Ok(Err(error)) if !error.is::<fictionet::Cancelled>() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(_) => Err("the fixture world panicked".into()),
    }
}
