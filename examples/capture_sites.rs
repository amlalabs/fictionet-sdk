// The packets between the sandboxes and `web::Sites`, written to a pcap
// file that tshark and Wireshark open. The world prints a line when a
// packet could not be written. Controlled shutdown drains the writer; an
// abrupt exit can truncate the pcap.
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
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}, writing packets to {pcap}");

    // The file is written on a thread of its own. A world's tasks share
    // one thread, and a write can block, so the filter only hands each
    // packet to this channel, which never waits.
    let (tx, rx) = sync_channel::<(Duration, Vec<u8>)>(1024);
    let lost = Arc::new(AtomicU64::new(0));
    let mut file = std::io::BufWriter::new(std::fs::File::create(&pcap)?);
    // The pcap header: version 2.4, packets up to 65,535 bytes, raw IP.
    for word in [0xa1b2_c3d4u32, 0x0004_0002, 0, 0, 65_535, LINKTYPE_RAW] {
        file.write_all(&word.to_le_bytes())?;
    }
    file.flush()?;
    let writer_lost = lost.clone();
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let writer = std::thread::spawn(move || {
        let result = write_packets(file, rx, writer_lost);
        if let Err(error) = &result {
            eprintln!("capture: writing {pcap} failed: {error}");
        }
        result
    });
    let result = fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let app = axum::Router::new()
                .route("/", axum::routing::get(|| async { "hello, captured\n" }));

            let watched = attachments.map(&fcx, move |fcx, sandbox| {
                let (tx, lost) = (tx.clone(), lost.clone());
                stdlib::network::filter(fcx, sandbox, move |fcx, _direction, packet| {
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
    ));
    writer
        .join()
        .map_err(|_| std::io::Error::other("capture writer panicked"))??;
    result
}

fn write_packets(
    mut file: impl Write,
    rx: std::sync::mpsc::Receiver<(Duration, Vec<u8>)>,
    writer_lost: Arc<AtomicU64>,
) -> std::io::Result<()> {
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
            Err(TryRecvError::Disconnected) => return file.flush(),
        };
        let len = packet.len() as u32;
        for word in [at.as_secs() as u32, at.subsec_micros(), len, len] {
            file.write_all(&word.to_le_bytes())?;
        }
        file.write_all(&packet)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controlled_shutdown_drains_and_flushes_queued_packets() {
        #[derive(Clone, Default)]
        struct Output(Arc<std::sync::Mutex<(Vec<u8>, bool)>>);
        impl Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().1 = true;
                Ok(())
            }
        }
        let output = Output::default();
        let sink = output.clone();
        let (tx, rx) = sync_channel(2);
        tx.send((Duration::from_secs(1), vec![1, 2, 3])).unwrap();
        tx.send((Duration::from_secs(2), vec![4, 5])).unwrap();
        drop(tx);
        let writer =
            std::thread::spawn(move || write_packets(sink, rx, Arc::new(AtomicU64::new(0))));
        writer.join().unwrap().unwrap();
        let out = output.0.lock().unwrap();
        assert_eq!(out.0.len(), 16 + 3 + 16 + 2);
        assert_eq!(&out.0[16..19], &[1, 2, 3]);
        assert_eq!(&out.0[35..], &[4, 5]);
        assert!(out.1, "disconnect flushes buffered output");
    }
}
