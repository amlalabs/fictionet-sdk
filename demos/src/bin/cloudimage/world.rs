//! The world the guest lives in: it hands out DHCP, resolves its names, and
//! serves an HTTPS site with the look-alike Zscaler chain. The guest's
//! network card reaches it through the vhost-user backend, whose frames this
//! module bridges into `stdlib::network::ethernet` and on to the world's
//! sandbox.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use example_common::web_world::{SHARED, app};
use example_common::zscaler::{DEFAULT_CLOUD, zscaler};
use fictionet::stdlib::network::ethernet::{Family, FromVm, Link};
use fictionet::stdlib::web;
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, RecvError, Result, Seed};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::sync::oneshot;

use crate::net::{self, RxQueue};

/// The MAC the guest's card uses; the world learns it from the first frame.
pub const GUEST_MAC: &str = "02:00:00:00:00:02";
const GUEST_MAC_BYTES: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
/// The IP MTU of the guest's card.
const MTU: u16 = 1500;

/// How to start the world.
pub struct Config {
    /// The run's wall-clock time, for certificate validity and the `Date`
    /// header.
    pub now_unix: i64,
    /// The HTTPS site name the guest fetches.
    pub site: String,
    /// The Unix socket the vhost-user-net backend listens on.
    pub net_socket: PathBuf,
}

/// A running world. [`shutdown`](World::shutdown) stops it.
pub struct World {
    /// The CA root in PEM, for the guest's trust store.
    pub ca_pem: String,
    fcx: Cx,
    /// Set once the world answers an `http.request` for the site, which is
    /// Firefox's GET (nothing else fetches it over HTTP).
    firefox_loaded: Arc<AtomicBool>,
}

impl World {
    /// Whether Firefox has loaded the site, seen in the world's events.
    pub fn firefox_loaded(&self) -> bool {
        self.firefox_loaded.load(Ordering::SeqCst)
    }

    /// Cancels the world and its bridge.
    pub fn shutdown(self) {
        self.fcx.cancel();
    }
}

/// Starts the world and the frame bridge, and returns once the CA is minted.
pub async fn start(config: Config) -> Result<World> {
    let (attacher, attachments) = fictionet::attachments();
    let sandbox = attacher.attach("agent")?;

    // The backend hands guest frames to the bridge over this channel, and
    // takes frames for the guest from the shared queue.
    let (to_world_tx, to_world_rx) = unbounded_channel::<Vec<u8>>();
    let rx = RxQueue::new()?;
    let _backend = net::start(&config.net_socket, GUEST_MAC_BYTES, to_world_tx, rx.clone())?;

    let now_unix = config.now_unix;
    let site = config.site.clone();
    let now_sys = SystemTime::UNIX_EPOCH + Duration::from_secs(now_unix as u64);
    let firefox_loaded = Arc::new(AtomicBool::new(false));

    let (ready, world_ready) = oneshot::channel();
    let loaded = firefox_loaded.clone();
    tokio::spawn(fictionet::run(Seed::random(), move |fcx| async move {
        let z = zscaler(&fcx, DEFAULT_CLOUD, now_unix)?;
        let www = format!("www.{site}");
        let site_cfg = z.server_config(&fcx, &[site.as_str(), www.as_str()], now_sys, now_unix)?;
        // The Zscaler leaf the world presents for Mozilla's HTTPS mirror.
        let mozilla_cfg = z.server_config(&fcx, &["packages.mozilla.org"], now_sys, now_unix)?;
        if ready.send((z.root_pem().to_string(), fcx.clone())).is_err() {
            return Ok(());
        }
        // Firefox's GET of the site, seen in the world's http.request events.
        let site_name = site.clone();
        fcx.events().subscribe(move |e| {
            if e.source == "http"
                && e.kind == "request"
                && e.str("host") == Some(site_name.as_str())
            {
                loaded.store(true, Ordering::SeqCst);
            }
        });
        // The apt mirror: the world forwards these names to the real servers
        // over the host's network, so the guest installs the desktop at
        // boot. apt's signatures verify everything.
        let mirror = web::proxy(&fcx)?;
        web::Sites::new(move |host: &str| match host {
            h if h == site || h == www => {
                Some(web::Site::new(app()).at(SHARED).tls(site_cfg.clone()))
            }
            "archive.ubuntu.com" | "security.ubuntu.com" | "ports.ubuntu.com" => {
                Some(web::Site::new(mirror.clone()))
            }
            "packages.mozilla.org" => Some(web::Site::new(mirror.clone()).tls(mozilla_cfg.clone())),
            _ => None,
        })
        .date(now_sys)
        .start(&fcx, attachments)
    }));

    let (ca_pem, fcx) = world_ready
        .await
        .map_err(|_| fictionet::Error::msg("the world stopped before it was ready"))?;

    tokio::spawn(bridge(to_world_rx, rx, sandbox, fcx.clone()));
    Ok(World {
        ca_pem,
        fcx,
        firefox_loaded,
    })
}

/// Moves frames between the guest (through the backend) and the world,
/// answering ARP and the link-local questions itself, as the CLI's tun
/// lowering does.
async fn bridge(mut to_world: UnboundedReceiver<Vec<u8>>, rx: RxQueue, mut sandbox: End, fcx: Cx) {
    let mut link = Link::new(Family::FromWorld, Family::Off, MTU);
    loop {
        tokio::select! {
            frame = to_world.recv() => {
                let Some(frame) = frame else { break };
                match link.frame_from_vm(&frame) {
                    FromVm::World(packet) => sandbox.send(Packet(packet.to_vec())),
                    FromVm::Answer(reply) => rx.push(reply),
                    FromVm::Drop(_) => {}
                }
            }
            packet = sandbox.recv(&fcx) => {
                match packet {
                    Ok(packet) => {
                        if let Some(header) = link.to_vm(&packet.0) {
                            let mut frame = header.to_vec();
                            frame.extend_from_slice(&packet.0);
                            rx.push(frame);
                        }
                    }
                    Err(RecvError::Closed | RecvError::Cancelled) => break,
                }
            }
        }
    }
}
