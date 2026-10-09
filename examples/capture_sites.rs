// The packets between the sandboxes and `web::Sites`, written to a pcap
// file that tshark and Wireshark open. The world prints a line when a
// packet could not be written.
//
//     cargo run --example capture_sites -- /run/fictionet/world.sock /run/fictionet/agent.pcap

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{TryRecvError, sync_channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::{self, web};

/// The link type of a pcap file whose packets start at the IP header,
/// IPv4 or IPv6 (LINKTYPE_RAW).
const LINKTYPE_RAW: u32 = 101;

fn main() -> fictionet::Result {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let pcap = args
        .next()
        .unwrap_or_else(|| "/run/fictionet/agent.pcap".into());
    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )?;
    println!("listening on {path}, writing packets to {pcap}");

    // The file is written on a thread of its own. A world's tasks share
    // one thread, and a write can block, so the filter only hands each
    // packet to this channel, which never waits.
    let (tx, rx) = sync_channel::<(Duration, Vec<u8>)>(100_000);
    let lost = Arc::new(AtomicU64::new(0));
    let mut file = std::io::BufWriter::new(std::fs::File::create(&pcap)?);
    // The pcap header: version 2.4, packets up to 65,535 bytes, raw IP.
    for word in [0xa1b2_c3d4u32, 0x0004_0002, 0, 0, 65_535, LINKTYPE_RAW] {
        file.write_all(&word.to_le_bytes())?;
    }
    file.flush()?;
    let writer_lost = lost.clone();
    let mut writer = move || -> std::io::Result<()> {
        let mut reported = 0;
        loop {
            let (at, packet) = match rx.try_recv() {
                Ok(p) => p,
                // Nothing waiting: write out what is buffered, then wait.
                Err(TryRecvError::Empty) => {
                    file.flush()?;
                    let n = writer_lost.load(Ordering::Relaxed);
                    if n != reported {
                        reported = n;
                        println!("capture: {n} packets not captured, because the channel was full");
                    }
                    match rx.recv() {
                        Ok(p) => p,
                        Err(_) => return Ok(()),
                    }
                }
                Err(TryRecvError::Disconnected) => return Ok(()),
            };
            let len = packet.len() as u32;
            for word in [at.as_secs() as u32, at.subsec_micros(), len, len] {
                file.write_all(&word.to_le_bytes())?;
            }
            file.write_all(&packet)?;
        }
    };
    let pcap_path = pcap.clone();
    std::thread::spawn(move || {
        if let Err(e) = writer() {
            eprintln!(
                "capture: writing {pcap_path} failed, so later packets are not captured: {e}"
            );
        }
    });

    let start = SystemTime::now().duration_since(UNIX_EPOCH)?;
    fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let app = axum::Router::new()
                .route("/", axum::routing::get(|| async { "hello, captured\n" }));

            let watched = attachments.map(&fcx, move |fcx, sandbox| {
                let (tx, lost) = (tx.clone(), lost.clone());
                stdlib::filter(fcx, sandbox, move |fcx, _direction, packet| {
                    let at = start + fcx.now().since_start();
                    if tx.try_send((at, packet.0.clone())).is_err() {
                        lost.fetch_add(1, Ordering::Relaxed);
                    }
                    true // pass every packet on
                })
            });

            web::Sites::new(move |host: &str| match host {
                "example.test" => Some(web::Site::new(app.clone())),
                _ => None,
            })
            .start(&fcx, watched)?;
            Ok(())
        },
    ))
}
