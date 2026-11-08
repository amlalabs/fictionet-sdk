//! One executable for world, prepared TUN, and guest VFIO attachments.

mod deploy;

use std::time::Duration;

use deploy::{Backend, Options, State};
use honeypot_world::evidence::{Metrics, Writer, WriterConfig};
use honeypot_world::{Clock, observe::Sinks};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn main() -> fictionet::Result {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if matches!(arguments.as_slice(), [arg] if arg == "--help" || arg == "-h") {
        print!("{}", deploy::HELP);
        return Ok(());
    }
    if matches!(arguments.as_slice(), [arg] if arg == "--version") {
        println!(
            "honeypot {} backends=world{}{}",
            env!("CARGO_PKG_VERSION"),
            if cfg!(target_os = "linux") {
                ",tun"
            } else {
                ""
            },
            if cfg!(all(target_os = "linux", feature = "raw-virtio")) {
                ",vfio-virtio"
            } else {
                ""
            }
        );
        return Ok(());
    }
    let options = Options::parse(arguments)?;
    if options.dry_run {
        println!("{}", serde_json::to_string_pretty(&options.summary())?);
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(options))
}

async fn run(mut options: Options) -> fictionet::Result {
    let state = State::open(&options.state_dir)?;
    options.args.config.ssh_host_key = Some(state.host_key);
    options.args.config.restricted_evidence = options.restricted_evidence;
    let (mut writer, sinks) = Writer::open(WriterConfig {
        state_dir: options.state_dir.clone(),
        sensor_id: state.sensor_id.clone(),
        backend: options.backend.name().into(),
        persona: format!(
            "ubuntu-24.04-linux-6.8-{:?}",
            options.args.config.http_profile
        )
        .to_lowercase(),
        capture_boundary: if matches!(options.backend, Backend::Vfio { .. }) {
            "ethernet_and_derived_ip"
        } else {
            "ip"
        }
        .into(),
        queue_bytes: options.queue_bytes,
        max_record_bytes: options.max_record_bytes,
        rotate_bytes: options.rotate_bytes,
        retain_files: options.retain_files,
        restricted_evidence: options.restricted_evidence,
        ..WriterConfig::default()
    })?;
    writer.record(&options.summary())?;
    let result = serve(&options, &mut writer, sinks).await;
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

async fn serve(options: &Options, writer: &mut Writer, sinks: Sinks) -> fictionet::Result {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let metrics = match options.metrics {
        Some(address) => Some(tokio::net::TcpListener::bind(address).await?),
        None => None,
    };
    let config = options.args.config.clone();
    let clock = Clock::starting_now();
    let health = writer.metrics_handle();
    let mut listening = None;
    #[cfg(target_os = "linux")]
    let mut tun = None;
    #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
    let mut raw = None;
    #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
    let mut pump = None;
    let attachments = match &options.backend {
        Backend::World => {
            let (listener, attachments) = fictionet::Listening::bind(options.args.world.clone())?;
            listening = Some(listener);
            Some(attachments)
        }
        Backend::Tun { name, create } => {
            #[cfg(target_os = "linux")]
            {
                use fictionet_host::tun::{Mode, Tun};
                let device = Tun::open(
                    name,
                    if *create {
                        Mode::Create
                    } else {
                        Mode::Existing
                    },
                )?;
                let (attacher, attachments) = fictionet::attachments();
                let end = attacher.attach(honeypot_world::INTERNET)?;
                tun = Some((device, end, attacher));
                Some(attachments)
            }
            #[cfg(not(target_os = "linux"))]
            return Err(fictionet::Error::msg("TUN requires Linux"));
        }
        Backend::Vfio { device: _device } => {
            #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
            {
                let (driver, attachment) = fictionet_host::raw::RawPump::attach(
                    fictionet_host::VirtioNet::open(_device.parse()?)?,
                )?;
                pump = Some(driver);
                raw = Some(attachment);
                None
            }
            #[cfg(not(all(target_os = "linux", feature = "raw-virtio")))]
            return Err(fictionet::Error::msg(
                "VFIO virtio-net unavailable in this build",
            ));
        }
    };
    writer.record(&json!({"event": "backend_attached", "public_reachability": "not_tested"}))?;
    #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
    let raw_sink = writer.raw_sink();
    let result = fictionet::run(fictionet::Seed::random(), move |fcx| {
        let started = match attachments {
            Some(attachments) => honeypot_world::start(&fcx, &config, clock, sinks, attachments),
            #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
            None => honeypot_world::start_raw(&fcx, &config, clock, sinks, raw.expect("VFIO attachment"), raw_sink),
            #[cfg(not(all(target_os = "linux", feature = "raw-virtio")))]
            None => unreachable!(),
        };
        if started.is_ok() {
            #[cfg(target_os = "linux")]
            if let Some((tun, end, attacher)) = tun {
                fcx.spawn(move |fcx| async move {
                    let _attacher = attacher;
                    tun.relay(fcx, end).await
                });
            }
            if let Some(listener) = metrics { fcx.spawn(move |fcx| metrics_server(fcx, listener, health)); }
            fcx.spawn(move |fcx| async move {
                fcx.race(None, async { tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} } }).await?;
                fcx.cancel();
                Ok(())
            });
            let ready = json!({"event": "local_ready", "backend": options.backend.name(), "run_id": writer.run_id(), "public_reachability": "not_tested"});
            if let Err(error) = writer.record(&ready) { return std::future::ready(Err(error.into())); }
            writer.set_ready(true);
            println!("{ready}");
        }
        std::future::ready(started.map(drop))
    }).await;
    drop(listening);
    #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
    if let Some(driver) = pump {
        driver.shutdown()?;
    }
    result
}

async fn metrics_server(
    fcx: fictionet::Cx,
    listener: tokio::net::TcpListener,
    metrics: Metrics,
) -> fictionet::Result {
    loop {
        let (mut socket, _) = fcx.race(None, listener.accept()).await??;
        let request = async {
            let mut buffer = [0; 1024];
            let count = socket.read(&mut buffer).await?;
            let (status, body) = if buffer[..count].starts_with(b"GET /metrics HTTP/1.") {
                ("200 OK", metrics.prometheus())
            } else {
                ("404 Not Found", String::new())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await
        };
        let _ = fcx
            .race(None, tokio::time::timeout(Duration::from_secs(2), request))
            .await?;
    }
}
