//! The world the guest lives in: it hands out DHCP, resolves its names, and
//! serves an HTTPS site with the look-alike Zscaler chain. The guest's
//! network card reaches it through the vhost-user backend, whose frames this
//! module bridges into `stdlib::network::ethernet` and on to the world's
//! sandbox.
//!
//! The world also holds the admin's jump host, the machine the demo reaches
//! the guest from: its SSH session, and the VNC that session carries, cross
//! the world's network to the address the guest leased, as an admin's would.
//!
//! A `DashboardObserver` collects alongside the demo's event observers.
//! `Config::observation` serves its handle on a private Unix socket with
//! `fictionet_observe::serve`. Connect with
//! `fictionet observe --observation unix:PATH watch`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use example_common::web_world::{SHARED, app};
use example_common::zscaler::{DEFAULT_CLOUD, zscaler};
use fictionet::events::{Event, Fanout, Observation, Observer, Stamp};
use fictionet::stdlib::network::ethernet::{Family, FromVm, Link};
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::network::tcp::{self, TcpConnection};
use fictionet::stdlib::web;
use fictionet::tokio::{Compat, ConnectionTokioExt};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, RecvError, Result, RunOptions, Seed};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::sync::{oneshot, watch};

use crate::net::{self, RxQueue};

/// The MAC the guest's card uses; the world learns it from the first frame.
pub const GUEST_MAC: &str = "02:00:00:00:00:02";
const GUEST_MAC_BYTES: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
/// The IP MTU of the guest's card.
const MTU: u16 = 1500;
/// The guest's attachment.
const GUEST: &str = "agent";
/// The admin's jump host: a machine on the office's management subnet, the
/// address the guest's sshd sees every admin session come from.
pub const JUMP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 10, 5, 20);
/// The jump host's attachment, routed to [`JUMP_ADDR`].
const JUMP: &str = "jump";

/// How to start the world.
pub struct Config {
    /// The optional fifth command argument: a Unix socket for the collector.
    /// `fictionet observe --observation unix:PATH watch` follows its output.
    pub observation: Option<PathBuf>,
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
    _observation: Option<fictionet_observe::Endpoint>,
    /// The CA root in PEM, for the guest's trust store.
    pub ca_pem: String,
    fcx: Cx,
    /// Set once the world answers an `http.request` for the site with
    /// Firefox's User-Agent.
    firefox_loaded: Arc<AtomicBool>,
    /// The guest's address, once the world has leased it by DHCP.
    lease: watch::Receiver<Option<Ipv4Addr>>,
    /// The jump host's TCP.
    jump: tcp::Endpoint,
}

impl World {
    /// Whether Firefox has loaded the site, seen in the world's events.
    pub fn firefox_loaded(&self) -> bool {
        self.firefox_loaded.load(Ordering::SeqCst)
    }

    /// The address the world leased the guest by DHCP, if it has.
    pub fn guest_addr(&self) -> Option<Ipv4Addr> {
        *self.lease.borrow()
    }

    /// Opens a TCP connection from the jump host to the guest's `port`
    /// through the world's network, once the guest has its lease, as tokio
    /// I/O. Fails if the guest refuses it or does not answer in `timeout`.
    pub async fn connect_guest(
        &self,
        port: u16,
        timeout: Duration,
    ) -> io::Result<Compat<TcpConnection>> {
        let mut lease = self.lease.clone();
        let addr = lease
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|addr| *addr)
            .ok_or_else(|| io::Error::other("the world stopped before the guest had a lease"))?;
        let to = SocketAddr::from((addr, port));
        let conn = tokio::time::timeout(timeout, self.jump.connect(&self.fcx, to))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, format!("{to} did not answer"))
            })??;
        Ok(conn.into_tokio(&self.fcx))
    }

    /// Cancels the world and its bridge.
    pub fn shutdown(self) {
        self.fcx.cancel();
    }
}

/// Watches the world's `http.request` events for Firefox's GET of the site.
/// The coding agents' checks fetch the site too, so the request must carry
/// Firefox's User-Agent.
struct SiteLoaded {
    host: String,
    loaded: Arc<AtomicBool>,
}

impl Observer for SiteLoaded {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(metadata, _connection) = interest else {
            return false;
        };
        metadata.source == "http" && metadata.kind == "request"
    }

    fn observe(&self, _stamp: Stamp, observation: Observation<'_>) {
        if let Observation::Event(event) = observation
            && event.str("host") == Some(self.host.as_str())
            && user_agent(event).is_some_and(|agent| agent.contains("Firefox/"))
        {
            self.loaded.store(true, Ordering::SeqCst);
        }
    }
}

/// The `User-Agent` of an `http.request` event, from its header pairs.
fn user_agent(event: &Event) -> Option<&str> {
    event.get("headers")?.as_array()?.iter().find_map(|pair| {
        let [name, value] = pair.as_array()? else {
            return None;
        };
        (name.as_str()? == "user-agent")
            .then(|| value.as_str())
            .flatten()
    })
}

/// Watches the world's `net.bound` events for the address it leases the
/// guest by DHCP.
struct Lease {
    addr: watch::Sender<Option<Ipv4Addr>>,
}

impl Observer for Lease {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(metadata, connection) = interest else {
            return false;
        };
        metadata.source == "net"
            && metadata.kind == "bound"
            && connection
                .sandbox
                .as_ref()
                .is_some_and(|s| &*s.name == GUEST)
    }

    fn observe(&self, _stamp: Stamp, observation: Observation<'_>) {
        if let Observation::Event(event) = observation
            && event.get("by_dhcp").and_then(|v| v.as_bool()) == Some(true)
            && let Some(addr) = event.conn.sandbox.as_ref().and_then(|s| s.addr)
        {
            self.addr.send_replace(Some(addr));
        }
    }
}

/// Starts the world and the frame bridge, and returns once the CA is minted.
pub async fn start(config: Config) -> Result<World> {
    let (attacher, attachments) = fictionet::attachments();
    let sandbox = attacher.attach(GUEST)?;
    let jump_link = attacher.attach(JUMP)?;

    // The backend hands guest frames to the bridge over this channel, and
    // takes frames for the guest from the shared queue.
    let (to_world_tx, to_world_rx) = unbounded_channel::<Vec<u8>>();
    let rx = RxQueue::new()?;
    let _backend = net::start(&config.net_socket, GUEST_MAC_BYTES, to_world_tx, rx.clone())?;

    let now_unix = config.now_unix;
    let site = config.site.clone();
    let now_sys = SystemTime::UNIX_EPOCH + Duration::from_secs(now_unix as u64);
    let firefox_loaded = Arc::new(AtomicBool::new(false));
    let (lease_tx, lease) = watch::channel(None);

    let (ready, world_ready) = oneshot::channel();
    // The demo's observers; an integrator's own join them here.
    let dashboard =
        fictionet_observe::DashboardObserver::new(fictionet_observe::DashboardOptions::demo());
    let observation = config
        .observation
        .as_ref()
        .map(|path| fictionet_observe::serve(dashboard.handle(), path))
        .transpose()?;
    let observers: Vec<Arc<dyn Observer>> = vec![
        dashboard.observer(),
        Arc::new(SiteLoaded {
            host: site.clone(),
            loaded: firefox_loaded.clone(),
        }),
        Arc::new(Lease { addr: lease_tx }),
    ];
    let options = RunOptions::new(Seed::random()).observer(Arc::new(Fanout::new(observers)));
    tokio::spawn(fictionet::run(options, move |fcx| async move {
        let z = zscaler(&fcx, DEFAULT_CLOUD, now_unix)?;
        let www = format!("www.{site}");
        let site_cfg = z.server_config(&fcx, &[site.as_str(), www.as_str()], now_sys, now_unix)?;
        // The Zscaler leaves the world presents for the HTTPS download hosts:
        // Mozilla's apt repository, and the release servers the guest
        // installs Claude Code and Codex from.
        let mozilla_cfg = z.server_config(&fcx, &["packages.mozilla.org"], now_sys, now_unix)?;
        let claude_cfg = z.server_config(&fcx, &["downloads.claude.ai"], now_sys, now_unix)?;
        let openai_cfg = z.server_config(&fcx, &["releases.openai.com"], now_sys, now_unix)?;
        // The jump host: a machine of the world's own, on a trusted route
        // to its address. No host of the world serves the admin flows, so
        // they make no service events, but they cross the router and the
        // guest's link, and link counts and packet captures include them.
        // An integrator who wants them tagged or left out wraps this link
        // here (`stdlib::network::filter`) or filters on JUMP_ADDR.
        let jump = tcp::endpoint(&fcx, jump_link, JUMP_ADDR.into());
        if ready
            .send((z.root_pem().to_string(), fcx.clone(), jump))
            .is_err()
        {
            return Ok(());
        }
        // The mirror: the world forwards these names to the real servers over
        // the host's network, so the guest installs the desktop and the
        // coding agents at boot. apt's signatures verify the packages, and
        // the guest checks each agent download against its pinned sha256.
        let mirror = crate::mirror::new(&fcx)?;
        web::Sites::new(move |host: &str| match host {
            h if h == site || h == www => {
                Some(web::Site::new(app()).at(SHARED).tls(site_cfg.clone()))
            }
            "archive.ubuntu.com" | "security.ubuntu.com" | "ports.ubuntu.com" => {
                Some(web::Site::new(mirror.clone()))
            }
            "packages.mozilla.org" => Some(web::Site::new(mirror.clone()).tls(mozilla_cfg.clone())),
            "downloads.claude.ai" => Some(web::Site::new(mirror.clone()).tls(claude_cfg.clone())),
            "releases.openai.com" => Some(web::Site::new(mirror.clone()).tls(openai_cfg.clone())),
            _ => None,
        })
        .date(now_sys)
        .into_net()
        .route(
            JUMP,
            Prefix {
                addr: JUMP_ADDR.into(),
                len: 32,
            },
        )
        .start(&fcx, attachments)
    }));

    let (ca_pem, fcx, jump) = world_ready
        .await
        .map_err(|_| fictionet::Error::msg("the world stopped before it was ready"))?;

    tokio::spawn(bridge(to_world_rx, rx, sandbox, fcx.clone()));
    Ok(World {
        _observation: observation,
        ca_pem,
        fcx,
        firefox_loaded,
        lease,
        jump,
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
