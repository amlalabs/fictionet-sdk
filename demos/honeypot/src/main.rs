#![deny(unsafe_code)]

//! The honeypot executable: the world behind a raw Ethernet attachment,
//! with its evidence in a protected state directory.

// This module owns the host syscall boundary.
#[allow(unsafe_code)]
mod deploy;

use std::time::Duration;

use deploy::{Options, State};
use fictionet_host::raw::RawAttachment;
use honeypot_world::evidence::{Writer, WriterConfig};
use honeypot_world::{Clock, observe::Sinks};
use serde_json::json;

fn main() -> fictionet::Result {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", deploy::HELP);
        return Ok(());
    }
    if matches!(arguments.as_slice(), [arg] if arg == "--version") {
        println!("honeypot {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let options = Options::parse(arguments)?;
    let raw = attach()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(options, raw))
}

/// The network card the world's frames go through. This build has none,
/// so the honeypot refuses to start before it touches its state.
fn attach() -> fictionet::Result<RawAttachment> {
    Err(fictionet::Error::msg(
        "this build has no packet path; the honeypot cannot attach to a network",
    ))
}

async fn run(mut options: Options, raw: RawAttachment) -> fictionet::Result {
    let state = State::open(&options.state_dir)?;
    options.args.config.ssh_host_key = Some(state.host_key);
    options.args.config.restricted_evidence = options.restricted_evidence;
    let (mut writer, sinks) = Writer::open(WriterConfig {
        state_dir: options.state_dir.clone(),
        sensor_id: state.sensor_id.clone(),
        persona: format!(
            "ubuntu-24.04-linux-6.8-{:?}",
            options.args.config.http_profile
        )
        .to_lowercase(),
        queue_bytes: options.queue_bytes,
        max_record_bytes: options.max_record_bytes,
        rotate_bytes: options.rotate_bytes,
        retain_files: options.retain_files,
        restricted_evidence: options.restricted_evidence,
        ..WriterConfig::default()
    })?;
    writer.record(&options.summary())?;
    let result = serve(&options, &mut writer, sinks, raw).await;
    writer.set_ready(false);
    let _ = writer.record(&json!({"event": "shutdown", "status": if result.is_ok() { "stopped" } else { "failed" }, "error": result.as_ref().err().map(ToString::to_string)}));
    let metrics = writer.metrics_handle();
    let drained = writer.shutdown(Duration::from_secs(5));
    match &drained {
        Ok(snapshot) => eprintln!(
            "{}",
            json!({"event": "evidence_shutdown", "metrics": snapshot})
        ),
        Err(error) => eprintln!(
            "{}",
            json!({"event": "evidence_shutdown", "error": error.to_string(), "metrics": metrics.snapshot()})
        ),
    }
    result?;
    drained?;
    Ok(())
}

async fn serve(
    options: &Options,
    writer: &mut Writer,
    sinks: Sinks,
    raw: RawAttachment,
) -> fictionet::Result {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let config = options.args.config.clone();
    let clock = Clock::starting_now();
    writer.record(&json!({"event": "backend_attached", "public_reachability": "not_tested"}))?;
    let raw_sink = writer.raw_sink();
    fictionet::run(fictionet::Seed::random(), move |fcx| {
        let started = honeypot_world::start_raw(&fcx, &config, clock, sinks, raw, raw_sink);
        if started.is_ok() {
            fcx.spawn(move |fcx| async move {
                fcx.race(None, async { tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} } }).await?;
                fcx.cancel();
                Ok(())
            });
            let ready = json!({"event": "local_ready", "run_id": writer.run_id(), "public_reachability": "not_tested"});
            if let Err(error) = writer.record(&ready) { return std::future::ready(Err(error.into())); }
            writer.set_ready(true);
            println!("{ready}");
        }
        std::future::ready(started.map(drop))
    }).await
}
