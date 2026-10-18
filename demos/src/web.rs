//! The web demo: the quick-start world of `examples/web_world.rs`, and a
//! guest that takes an address from it by DHCP, resolves its names with
//! its DNS server, and fetches its HTTPS site with its CA.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use example_common::web_world::{app, certificates, plain, sites};
use fictionet::stdlib::web;
use fictionet::{Error, Result, Seed};
use fictionet_microvm::{Agent, Assets, Config, Vm};

use crate::frames;

/// How long the guest has to boot and start its agent.
const BOOT: Duration = Duration::from_secs(30);
/// How long the guest has to power off before its child is killed.
const SHUTDOWN: Duration = Duration::from_secs(10);

pub async fn run(assets: Assets) -> Result {
    let (attacher, attachments) = fictionet::attachments();
    let sandbox = attacher.attach("agent")?;
    let (ready, world_ready) = tokio::sync::oneshot::channel();
    let world = tokio::spawn(fictionet::run(
        fictionet::RunOptions::new(Seed::random())
            .aggregate_events()
            .event_history(std::sync::Arc::new(fictionet::events::Memory::default())),
        move |fcx| async move {
            let (ca, leaf) = certificates(&fcx)?;
            // The guest gets the CA before it boots, so its agent can install
            // it in the trust store.
            if ready.send((ca.cert_pem(), fcx.clone())).is_err() {
                return Ok(());
            }
            web::Sites::new(sites(&fcx, leaf.chain, leaf.key, app(), plain())?)
                .start(&fcx, attachments)
        },
    ));
    let (ca_pem, fcx) = world_ready
        .await
        .map_err(|_| Error::msg("the world stopped before it was ready"))?;

    let started = Instant::now();
    let mut vm = Vm::start(
        &assets,
        &Config {
            vcpus: 2,
            memory_mib: 512,
            ca_pem: Some(ca_pem),
        },
    )?;
    let prepared = started.elapsed();
    let net = vm
        .take_net()
        .ok_or_else(|| Error::msg("the VM has no network card"))?;
    let frames = tokio::spawn(frames::run(net, sandbox, fcx.clone()));

    let outcome = match vm.agent(BOOT).await {
        Ok(agent) => {
            let ready = started.elapsed();
            let (kernel, init) = agent.boot_times();
            println!(
                "the guest agent is up: the kernel started it after {} ms, and it set up the guest in {} ms",
                kernel.as_millis(),
                init.as_millis()
            );
            let steps = steps(&agent, &vm, started).await;
            let stopped = vm.stop(agent, SHUTDOWN).await;
            match (steps, stopped) {
                (Ok(report), Ok(status)) => {
                    println!("\nthe guest powered off ({status}); the VM child is gone");
                    Ok((report, ready))
                }
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => Err(error.into()),
            }
        }
        Err(error) => {
            drop(vm);
            Err(error.into())
        }
    };
    // The world stops with its region; the frames end with the guest's
    // socket, which closed when the child exited.
    fcx.cancel();
    world.await.map_err(Error::from)??;
    let drops = frames.await.map_err(Error::from)??;
    let (report, ready) = outcome?;

    println!("\nmeasured:");
    println!(
        "  storage prepared, child started:  {:>6} ms",
        prepared.as_millis()
    );
    println!(
        "  guest agent ready:                {:>6} ms",
        ready.as_millis()
    );
    println!(
        "  DHCP lease from the world:        {:>6} ms",
        report.lease.as_millis()
    );
    println!(
        "  curl of https://example.test/ ok: {:>6} ms",
        report.curl.as_millis()
    );
    println!(
        "  memory: this process {} MiB resident (peak {} MiB); VM child {} MiB (peak {} MiB)",
        report.parent.0 >> 10,
        report.parent.1 >> 10,
        report.child.0 >> 10,
        report.child.1 >> 10,
    );
    println!(
        "  private storage: {} MiB of files, {} MiB on disk",
        report.storage.0 >> 20,
        report.storage.1 >> 20
    );
    if !drops.from_vm.is_empty() || drops.to_vm > 0 {
        println!("  frames dropped: {drops:?}");
    }
    Ok(())
}

/// What the steps measured, from the start of the VM.
struct Report {
    lease: Duration,
    curl: Duration,
    /// Resident and peak memory in KiB.
    parent: (u64, u64),
    child: (u64, u64),
    /// The VM's private files: their length and the space they take.
    storage: (u64, u64),
}

async fn steps(agent: &Agent, vm: &Vm, started: Instant) -> Result<Report> {
    // agentd brings up only the loopback; the card is the guest's to bring
    // up, and busybox's DHCP client does not.
    guest(agent, "ip", &["link", "set", "dev", "eth0", "up"]).await?;
    // busybox's DHCP client: in the foreground, giving up after five tries,
    // and gone once it has applied the lease with its script.
    guest(
        agent,
        "udhcpc",
        &["-i", "eth0", "-f", "-q", "-n", "-t", "5", "-T", "1"],
    )
    .await?;
    let lease = started.elapsed();
    guest(agent, "ip", &["-4", "addr", "show", "dev", "eth0"]).await?;
    guest(agent, "cat", &["/etc/resolv.conf"]).await?;
    guest(agent, "nslookup", &["example.test"]).await?;
    // No --cacert: the world's CA is in the guest's trust store.
    let page = guest(
        agent,
        "curl",
        &["-sS", "--max-time", "10", "https://example.test/"],
    )
    .await?;
    let curl = started.elapsed();
    if !page.starts_with("hello from https example.test 443") {
        return Err(Error::msg(format!("unexpected page: {page}")));
    }
    let pid = vm.pid().ok_or_else(|| Error::msg("the VM child is gone"))?;
    Ok(Report {
        lease,
        curl,
        parent: memory("self")?,
        child: memory(&pid.to_string())?,
        storage: storage(vm.dir())?,
    })
}

/// Runs a command in the guest, shows it and its output, and fails unless
/// it exits 0. Returns its standard output.
async fn guest(agent: &Agent, cmd: &str, args: &[&str]) -> Result<String> {
    println!("\nguest$ {cmd} {}", args.join(" "));
    let output = agent.exec(cmd, args).await?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if output.code != 0 {
        return Err(Error::msg(format!("{cmd} exited with {}", output.code)));
    }
    Ok(stdout)
}

/// Resident and peak memory of a process, in KiB.
fn memory(pid: &str) -> Result<(u64, u64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().trim_end_matches(" kB").parse().ok())
            .ok_or_else(|| Error::msg(format!("no {name} in /proc/{pid}/status")))
    };
    Ok((field("VmRSS:")?, field("VmHWM:")?))
}

/// The length of the files under `dir`, and the space they take.
fn storage(dir: &Path) -> Result<(u64, u64)> {
    let mut total = (0, 0);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            let (len, used) = storage(&entry.path())?;
            total = (total.0 + len, total.1 + used);
        } else {
            total = (total.0 + meta.len(), total.1 + meta.blocks() * 512);
        }
    }
    Ok(total)
}
