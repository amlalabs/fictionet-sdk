//! Shared guests, networking, provisioning, and run lifetime.
//!
//! ```no_run
//! use fictionet_demo::kit::{self, Guest, Kit};
//! use fictionet_observe::page::Page;
//! use fictionet::stdlib::web;
//! use example_common::zscaler::{DEFAULT_CLOUD, zscaler};
//! use std::time::{Duration, SystemTime};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let kit = Kit::new("office")
//!     .guest(kit::desktop::browser("workstation", "analyst", "http://archive.ubuntu.com"))
//!     .guest(Guest::ubuntu("server", "operator"))
//!     .page(|dashboard, hosts| Page::new("Office", dashboard)
//!         .host(hosts.take("workstation")).host(hosts.take("server")).standard_panels())
//!     .world(|fcx, mut world| async move {
//!         let now = world.now_unix();
//!         let date = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
//!         let ca = zscaler(&fcx, DEFAULT_CLOUD, now)?;
//!         let tls = ca.server_config(&fcx, kit::desktop::HOSTS, date)?;
//!         world.trust("office", ca.root_pem())?;
//!         let mirror = world.mirror(&fcx)?;
//!         web::Sites::new(move |host: &str| match host {
//!             "archive.ubuntu.com" | "security.ubuntu.com" => Some(web::Site::new(mirror.clone())),
//!             h if kit::desktop::HOSTS.contains(&h) => Some(web::Site::new(mirror.clone()).tls(tls.clone())),
//!             _ => None,
//!         }).date(date).into_net().route(kit::JUMP, kit::jump_prefix())
//!             .start(&fcx, world.into_attachments())
//!     });
//! let run = kit.boot("demos/downloads/cloudimage").await?;
//! let workstation = run.guest("workstation");
//! workstation.wait_cloud_init(Duration::from_secs(300)).await?;
//! workstation.wait_desktop(Duration::from_secs(300)).await?;
//! let (screen, page) = (run.path().join("desktop.png"), run.path().join("page.png"));
//! let shots = run.screenshots("workstation", &screen, &page).await?;
//! kit::checks::check("the screen is 1280 pixels wide", shots.screen.width == 1280)?;
//! run.shutdown().await?;
//! # Ok(())
//! # }
//! ```
//!
//! `Kit::page` adds the dashboard observer, containment probes and panel, labels
//! task and panel, and each host's status; for a browser guest, the world must
//! serve `kit::desktop::HOSTS` through `World::mirror`.

pub mod bridge;
pub mod checks;
pub mod client;
mod page;
pub use page::{Hosts, answer_command, serve_commands};
pub mod containment;
pub mod desktop;
pub mod jump;
pub mod mirror;
pub mod net;
pub mod preview;
pub mod rfb;
pub mod seed;
pub mod shot;
pub mod ssh;
mod util;
pub mod vm;

pub use util::random_uuid;

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fictionet_observe::page::{Containment, Labels, Page, Server, StateLimits, StateTopic};
use fictionet_observe::{DashboardHandle, DashboardObserver, DashboardOptions};

use fictionet::events::{Fanout, Interest, Observation, Observer, Stamp};
use fictionet::stdlib::network::ethernet::Family;
use fictionet::{Attachments, Cx, RunOptions, Seed};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

/// The admin attachment and route.
pub const JUMP: &str = "jump";
/// The largest IP packet a guest's card carries.
const MTU: u16 = 1500;
/// The route prefix for the admin jump host.
pub fn jump_prefix() -> fictionet::stdlib::network::route::Prefix {
    fictionet::stdlib::network::route::Prefix {
        addr: jump::JUMP_ADDR.into(),
        len: 32,
    }
}

/// Words nothing in a guest may contain, in any case: in its names, its
/// files, its packages or its commands. Any of them could tell an agent in
/// the guest that its world is made up. [`Guest::forbid`] adds a demo's own.
pub const FORBIDDEN: &[&str] = &[
    "fictionet",
    "eval",
    "sandbox",
    "world",
    "scripted",
    "demo",
    "probe",
];

#[derive(Clone)]
struct File {
    path: String,
    mode: u32,
    content: String,
}

/// A guest's identity, resources, card, and cloud-init steps.
#[derive(Clone)]
pub struct Guest {
    hostname: String,
    attachment: String,
    user: String,
    vcpus: u8,
    memory_mib: u32,
    manufacturer: String,
    product: String,
    family: Family<Ipv4Addr>,
    packages: Vec<String>,
    files: Vec<File>,
    steps: Vec<String>,
    desktop: Option<(u16, String)>,
    terminal: Option<String>,
    forbidden: Vec<String>,
}

impl Guest {
    /// Creates an Ubuntu guest with 2 vCPUs, 2048 MiB, and `Family::FromWorld`.
    /// DMI defaults to manufacturer `LENOVO` and product `20UES000-WS`.
    /// No additional packages, files, or commands are installed by default.
    pub fn ubuntu(hostname: &str, user: &str) -> Self {
        Self {
            hostname: hostname.into(),
            attachment: hostname.into(),
            user: user.into(),
            vcpus: 2,
            memory_mib: 2048,
            manufacturer: "LENOVO".into(),
            product: "20UES000-WS".into(),
            family: Family::FromWorld,
            packages: Vec::new(),
            files: Vec::new(),
            steps: Vec::new(),
            desktop: None,
            terminal: None,
            forbidden: Vec::new(),
        }
    }
    /// Sets the host-side attachment name independently of the guest hostname.
    pub fn attachment(mut self, name: &str) -> Self {
        self.attachment = name.into();
        self
    }
    /// Sets the vCPU count and memory in MiB, defaulting to 2 and 2048.
    pub fn resources(mut self, vcpus: u8, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }
    /// Sets DMI manufacturer and product, defaulting to `LENOVO` and `20UES000-WS`.
    pub fn dmi(mut self, manufacturer: &str, product: &str) -> Self {
        self.manufacturer = manufacturer.into();
        self.product = product.into();
        self
    }
    /// Sets the card family, defaulting to `Family::FromWorld` for DHCP.
    pub fn card(mut self, family: Family<Ipv4Addr>) -> Self {
        self.family = family;
        self
    }
    /// Adds packages to install after the shared trust store is ready.
    pub fn packages(mut self, packages: &[&str]) -> Self {
        self.packages.extend(packages.iter().map(|s| s.to_string()));
        self
    }
    /// Adds a file with Unix permission bits and UTF-8 content to the seed.
    pub fn file(mut self, path: &str, mode: u32, content: impl Into<String>) -> Self {
        self.files.push(File {
            path: path.into(),
            mode,
            content: content.into(),
        });
        self
    }
    /// Appends a shell command to run after package installation.
    pub fn run(mut self, command: impl Into<String>) -> Self {
        self.steps.push(command.into());
        self
    }
    /// Declares a loopback VNC port and a command that exits zero when the desktop is ready.
    pub fn desktop(mut self, port: u16, ready: impl Into<String>) -> Self {
        self.desktop = Some((port, ready.into()));
        self
    }
    /// Runs a command on the page terminal's PTY instead of a login shell.
    pub fn terminal(mut self, command: impl Into<String>) -> Self {
        self.terminal = Some(command.into());
        self
    }
    /// Adds words that nothing in this guest may contain, beside [`FORBIDDEN`].
    pub fn forbid(mut self, words: &[&str]) -> Self {
        self.forbidden
            .extend(words.iter().map(|w| w.to_ascii_lowercase()));
        self
    }
    /// Returns the first word of [`FORBIDDEN`] or [`Guest::forbid`] that
    /// `text` contains, ignoring case.
    pub fn reveals(&self, text: &str) -> Option<&str> {
        forbidden_in(text, &self.forbidden)
    }
    fn initial_addr(&self) -> Option<Ipv4Addr> {
        match &self.family {
            Family::Serve(lease) => Some(lease.addr.addr),
            _ => None,
        }
    }
    /// Checks the guest's card and resources, and that its names, DMI
    /// strings, files, packages and commands hold no forbidden word.
    pub fn validate(&self) -> io::Result<()> {
        for name in [&self.hostname, &self.user] {
            if !valid_name(name) || self.reveals(name).is_some() {
                return Err(io::Error::other(format!(
                    "invalid guest hostname or user: {name}"
                )));
            }
        }
        fictionet::stdlib::network::ethernet::Link::new(self.family.clone(), Family::Off, MTU)
            .map_err(|e| io::Error::other(format!("{}: invalid card: {e}", self.hostname)))?;
        if self.attachment.is_empty()
            || self.attachment == JUMP
            || self.vcpus == 0
            || self.memory_mib == 0
        {
            return Err(io::Error::other("guest name or resources are invalid"));
        }
        for value in [&self.manufacturer, &self.product] {
            if value.is_empty() || value.contains([',', '\n', '\r']) {
                return Err(io::Error::other(
                    "guest DMI strings must be one nonempty line",
                ));
            }
        }
        if let Some((port, ready)) = &self.desktop
            && (*port == 0 || ready.trim().is_empty() || ready.contains('\0'))
        {
            return Err(io::Error::other(
                "desktop needs a nonzero port and a nonempty readiness command",
            ));
        }
        if self
            .terminal
            .as_ref()
            .is_some_and(|command| command.trim().is_empty() || command.contains('\0'))
        {
            return Err(io::Error::other("terminal needs a nonempty command"));
        }
        let texts = [
            ("DMI string", &self.manufacturer),
            ("DMI string", &self.product),
        ]
        .into_iter()
        .chain(
            self.files
                .iter()
                .flat_map(|f| [("file path", &f.path), ("file", &f.content)]),
        )
        .chain(self.packages.iter().map(|p| ("package", p)))
        .chain(self.steps.iter().map(|s| ("command", s)))
        .chain(
            self.desktop
                .iter()
                .map(|(_, ready)| ("readiness command", ready)),
        )
        .chain(
            self.terminal
                .iter()
                .map(|command| ("terminal command", command)),
        );
        for (kind, text) in texts {
            if let Some(word) = self.reveals(text) {
                let line = text.lines().find(|l| self.reveals(l).is_some());
                return Err(io::Error::other(format!(
                    "{}: a guest {kind} contains the forbidden word {word:?}: {}",
                    self.hostname,
                    line.unwrap_or(text)
                )));
            }
        }
        Ok(())
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && forbidden_in(name, &[]).is_none()
}

/// The first word of [`FORBIDDEN`] or `extra` in `text`, ignoring case.
fn forbidden_in<'a>(text: &str, extra: &'a [String]) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    FORBIDDEN
        .iter()
        .copied()
        .chain(extra.iter().map(String::as_str))
        .find(|word| lower.contains(word))
}

/// Inputs available to a world author before any guest boots.
pub struct World {
    attachments: Attachments,
    ca: Arc<Mutex<Option<(String, String)>>>,
    now_unix: i64,
    mirror: Option<mirror::Cache<fictionet::stdlib::web::Proxy>>,
}

impl World {
    /// Returns the run start time as Unix seconds for certificate issuance.
    pub fn now_unix(&self) -> i64 {
        self.now_unix
    }
    /// Installs a named root certificate in each guest's system trust store.
    /// The name must contain only neutral ASCII letters, digits, hyphens, or underscores.
    pub fn trust(&mut self, name: &str, pem: &str) -> fictionet::Result {
        if !valid_name(name) {
            return Err(fictionet::Error::msg("invalid root certificate name"));
        }
        *self.ca.lock().unwrap() = Some((name.into(), pem.into()));
        Ok(())
    }
    /// Returns one shared cache for all hosts and guests in this run.
    pub fn mirror(
        &mut self,
        fcx: &Cx,
    ) -> fictionet::Result<mirror::Cache<fictionet::stdlib::web::Proxy>> {
        if self.mirror.is_none() {
            self.mirror = Some(mirror::new(fcx)?);
        }
        Ok(self.mirror.as_ref().unwrap().clone())
    }
    /// Returns the guest and jump host attachments for the world to serve.
    pub fn into_attachments(self) -> Attachments {
        self.attachments
    }
}

type PageBuilder = Box<dyn FnOnce(DashboardHandle, &mut Hosts) -> Page + Send>;

/// Declares guests and observers before starting the world.
pub struct Kit<W = ()> {
    name: String,
    guests: Vec<Guest>,
    observers: Vec<Arc<dyn Observer>>,
    world: W,
    page: Option<PageBuilder>,
    pub(crate) run_parent: PathBuf,
}

impl Kit {
    /// Creates a named kit with no guests or observers and temporary run storage.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            guests: Vec::new(),
            observers: Vec::new(),
            world: (),
            page: None,
            run_parent: std::env::temp_dir(),
        }
    }
}

impl<W> Kit<W> {
    /// Adds a guest with its world attachment.
    pub fn guest(mut self, guest: Guest) -> Self {
        self.guests.push(guest);
        self
    }
    /// Adds an observer to the fanout installed before the world starts.
    pub fn observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observers.push(observer);
        self
    }
    /// Builds a page before the world starts and before any guest boots.
    /// The kit adds containment results and labels and runs their world tasks.
    /// Do not call Page::containment or Page::labels in the builder; duplicate
    /// panels are rejected at bind. Guests need not all be taken by the page.
    pub fn page(
        mut self,
        build: impl FnOnce(DashboardHandle, &mut Hosts) -> Page + Send + 'static,
    ) -> Self {
        self.page = Some(Box::new(build));
        self
    }
    /// Sets the closure that starts the world services.
    /// It must return once services are started, as `Net::start` does, because
    /// boot waits for it before writing the guest seeds.
    pub fn world<F, Fut>(self, world: F) -> Kit<F>
    where
        F: FnOnce(Cx, World) -> Fut + Send + 'static,
        Fut: Future<Output = fictionet::Result> + Send + 'static,
    {
        Kit {
            name: self.name,
            guests: self.guests,
            observers: self.observers,
            world,
            page: self.page,
            run_parent: self.run_parent,
        }
    }
}

struct Resources {
    dir: PathBuf,
    socket: PathBuf,
    overlay: PathBuf,
    seed: PathBuf,
    mac: [u8; 6],
    uuid: String,
}

impl Resources {
    fn new(root: &Path, guest: &Guest, index: usize) -> io::Result<Self> {
        let dir = root.join(&guest.hostname);
        std::fs::create_dir(&dir)?;
        let number = u32::try_from(index + 2)
            .map_err(io::Error::other)?
            .to_be_bytes();
        Ok(Self {
            socket: dir.join("net.sock"),
            overlay: dir.join("overlay.qcow2"),
            seed: dir.join("seed.img"),
            dir,
            mac: [2, 0, number[0], number[1], number[2], number[3]],
            uuid: random_uuid(),
        })
    }
}

/// A running guest reached through the admin's SSH session.
pub struct GuestHandle {
    guest: Guest,
    resources: Resources,
    addr: watch::Receiver<Option<Ipv4Addr>>,
    vm: Option<vm::Vm>,
    ssh: Option<Arc<ssh::Session>>,
    backend: Option<net::Backend>,
    boot: Instant,
    ssh_ready: Duration,
    console: page::GuestConsole,
}

impl GuestHandle {
    /// Returns the guest hostname.
    pub fn name(&self) -> &str {
        &self.guest.hostname
    }
    /// Returns the fixed or observed DHCP address, if known.
    pub fn addr(&self) -> Option<Ipv4Addr> {
        *self.addr.borrow()
    }
    /// Returns the SSH session connected through the jump host.
    pub fn ssh(&self) -> &Arc<ssh::Session> {
        self.ssh.as_ref().expect("boot completed")
    }
    /// Returns the guest process and its diagnostics.
    pub fn vm(&self) -> &vm::Vm {
        self.vm.as_ref().expect("boot completed")
    }
    /// Waits up to timeout for the guest's desktop, with or without Kit::page.
    /// Returns elapsed time from VM startup. A timeout names the guest,
    /// readiness command, and the last attempt's exit code and stderr tail.
    pub async fn wait_desktop(&self, timeout: Duration) -> io::Result<Duration> {
        self.console.wait_desktop(timeout).await
    }
    /// Returns the elapsed time from VM startup until this guest accepted SSH.
    pub fn ssh_ready(&self) -> Duration {
        self.ssh_ready
    }
}

/// Owns every process, bridge, and temporary file of a run.
pub struct Run {
    guests: Vec<GuestHandle>,
    fcx: Arc<Mutex<Option<Cx>>>,
    world: Option<JoinHandle<fictionet::Result>>,
    jump: Option<Arc<jump::Jump>>,
    bridges: Vec<JoinHandle<()>>,
    dir: Option<util::RunDir>,
    boot: Instant,
    page: Option<Server>,
    dashboard: Option<DashboardHandle>,
    labels: Option<Labels>,
    containment: StateTopic<Containment>,
    probes: Arc<Mutex<Containment>>,
}

impl Run {
    /// Returns the signed page URL. Panics unless Kit::page was declared.
    pub fn page_url(&self) -> &str {
        self.page
            .as_ref()
            .expect("declare Kit::page before requesting its URL")
            .url()
    }
    /// Returns the page dashboard. Panics unless Kit::page was declared.
    pub fn dashboard(&self) -> DashboardHandle {
        self.dashboard
            .as_ref()
            .expect("declare Kit::page before requesting its dashboard")
            .clone()
    }
    /// Returns the named guest, panicking if it was not declared.
    pub fn guest(&self, name: &str) -> &GuestHandle {
        self.guests
            .iter()
            .find(|g| g.name() == name)
            .unwrap_or_else(|| panic!("guest {name} is not declared; add it with Kit::guest"))
    }
    /// Returns all guests in declaration order.
    pub fn guests(&self) -> &[GuestHandle] {
        &self.guests
    }
    /// Returns the instant VM startup began.
    pub fn boot_started(&self) -> Instant {
        self.boot
    }
    /// Returns the private run directory, removed during shutdown.
    pub fn path(&self) -> &Path {
        self.dir.as_ref().expect("running").path()
    }
    /// Powers guests off, reaps every VMM, cancels the world, and removes
    /// files. Fails unless every guest powered off, no Cloud Hypervisor
    /// process is left, and the run directory is gone.
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop_status();
        let pids: Vec<u32> = self
            .guests
            .iter()
            .filter_map(|guest| guest.vm.as_ref()?.pid())
            .collect();
        let mut failures = Vec::new();
        let mut stops = JoinSet::new();
        for guest in &mut self.guests {
            let ssh = guest.ssh.take();
            if let Some(vm) = guest.vm.take() {
                stops.spawn(async move {
                    // A guest that never answered SSH cannot be asked to
                    // power off, so it is killed at once.
                    let Some(ssh) = ssh else {
                        return vm.stop(Duration::ZERO).await;
                    };
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        ssh.run("sudo systemctl poweroff"),
                    )
                    .await;
                    vm.stop(Duration::from_secs(60)).await
                });
            }
        }
        while let Some(result) = stops.join_next().await {
            if let Err(error) = result.map_err(io::Error::other).and_then(|r| r) {
                failures.push(error.to_string());
            }
        }
        self.jump.take();
        if let Some(cx) = self.fcx.lock().unwrap().take() {
            cx.cancel();
        }
        for bridge in self.bridges.drain(..) {
            bridge.abort();
            let _ = bridge.await;
        }
        for guest in &mut self.guests {
            guest.backend.take();
        }
        if let Some(mut world) = self.world.take()
            && tokio::time::timeout(Duration::from_secs(5), &mut world)
                .await
                .is_err()
        {
            world.abort();
            let _ = world.await;
        }
        if let Some(dir) = self.dir.take()
            && let Err(error) = std::fs::remove_dir_all(dir.path())
        {
            failures.push(format!("{} remains: {error}", dir.path().display()));
        }
        for pid in pids {
            if Path::new(&format!("/proc/{pid}")).exists() {
                failures.push(format!("Cloud Hypervisor process {pid} remains"));
            }
        }
        if let Some(page) = self.page.take() {
            page.shutdown(Duration::from_secs(2)).await;
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "shutdown: {}",
                failures.join("; ")
            )))
        }
    }
}

impl Run {
    fn stop_status(&self) {
        if let Some(cx) = self.fcx.lock().unwrap().as_ref() {
            for guest in &self.guests {
                guest.console.stopped(cx);
            }
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        self.stop_status();
        if let Some(cx) = self.fcx.lock().unwrap().take() {
            cx.cancel();
        }
        if let Some(world) = &self.world {
            world.abort();
        }
        for bridge in &self.bridges {
            bridge.abort();
        }
        // Child's kill-on-drop is also active if the caller cancels boot.
        for guest in &mut self.guests {
            guest.vm.take();
            guest.backend.take();
        }
    }
}

struct Lease {
    name: String,
    addr: watch::Sender<Option<Ipv4Addr>>,
}

impl Observer for Lease {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(m, c)
            if m.source == "net" && m.kind == "bound"
                && c.sandbox.as_ref().is_some_and(|s| *s.name == self.name))
    }
    fn observe(&self, _: Stamp, item: Observation<'_>) {
        if let Observation::Event(event) = item
            && event.get("by_dhcp").and_then(|v| v.as_bool()) == Some(true)
            && let Some(addr) = event
                .conn
                .sandbox
                .as_ref()
                .filter(|s| *s.name == self.name)
                .and_then(|s| s.addr)
        {
            self.addr.send_replace(Some(addr));
        }
    }
}

type BackendInput = (tokio::sync::mpsc::UnboundedSender<Vec<u8>>, net::RxQueue);

struct Bridge {
    frames: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    queue: net::RxQueue,
    link: fictionet::End,
    family: Family<Ipv4Addr>,
}

struct Prepared {
    attachments: Attachments,
    jump_link: fictionet::End,
    bridges: Vec<Bridge>,
    backends: Vec<BackendInput>,
    observers: Vec<Arc<dyn Observer>>,
}

impl<W> Kit<W> {
    fn check_downloads(&self, downloads: &Path) -> io::Result<()> {
        for file in [
            "cloud-hypervisor",
            "ubuntu-24.04-server-cloudimg-amd64.img",
            "ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic",
            "ubuntu-24.04-server-cloudimg-amd64-initrd-generic",
        ] {
            if !downloads.join(file).is_file() {
                return Err(io::Error::other(format!(
                    "missing {}; run cargo xtask demo {}",
                    downloads.join(file).display(),
                    self.name
                )));
            }
        }
        Ok(())
    }

    fn prepare(&mut self) -> io::Result<(Run, Prepared)> {
        if self.guests.is_empty() {
            return Err(io::Error::other("declare at least one guest"));
        }
        let mut names = std::collections::HashSet::new();
        let mut attachments = std::collections::HashSet::new();
        for guest in &self.guests {
            guest.validate()?;
            if !names.insert(&guest.hostname) || !attachments.insert(&guest.attachment) {
                return Err(io::Error::other("duplicate guest hostname or attachment"));
            }
        }
        let mut run = Run {
            guests: Vec::new(),
            fcx: Arc::new(Mutex::new(None)),
            world: None,
            jump: None,
            bridges: Vec::new(),
            dir: Some(util::RunDir::new(&self.run_parent, &self.name)?),
            boot: Instant::now(),
            page: None,
            dashboard: None,
            labels: None,
            containment: StateTopic::new(StateLimits::default()),
            probes: Arc::new(Mutex::new(Containment::default())),
        };
        let (attacher, attachments) = fictionet::attachments();
        let mut prepared = Prepared {
            attachments,
            jump_link: attacher.attach(JUMP).map_err(io::Error::other)?,
            bridges: Vec::new(),
            backends: Vec::new(),
            observers: std::mem::take(&mut self.observers),
        };
        for (index, guest) in self.guests.drain(..).enumerate() {
            let resources = Resources::new(run.path(), &guest, index)?;
            let link = attacher
                .attach(&guest.attachment)
                .map_err(io::Error::other)?;
            let (tx, frames) = tokio::sync::mpsc::unbounded_channel();
            let queue = net::RxQueue::new()?;
            prepared.backends.push((tx, queue.clone()));
            prepared.bridges.push(Bridge {
                frames,
                queue,
                link,
                family: guest.family.clone(),
            });
            let (tx, addr) = watch::channel(guest.initial_addr());
            prepared.observers.push(Arc::new(Lease {
                name: guest.attachment.clone(),
                addr: tx,
            }));
            let console = page::GuestConsole::new(&guest);
            run.guests.push(GuestHandle {
                console,
                guest,
                resources,
                addr,
                vm: None,
                ssh: None,
                backend: None,
                boot: Instant::now(),
                ssh_ready: Duration::ZERO,
            });
        }
        Ok((run, prepared))
    }
}

impl<W, F> Kit<W>
where
    W: FnOnce(Cx, World) -> F + Send + 'static,
    F: Future<Output = fictionet::Result> + Send + 'static,
{
    /// Boots all guests and returns once every SSH session is ready.
    /// Missing downloads report the corresponding `cargo xtask demo` command.
    pub async fn boot(mut self, downloads: impl AsRef<Path>) -> io::Result<Run> {
        let downloads = downloads.as_ref();
        self.check_downloads(downloads)?;
        let identity = Arc::new(ssh::Identity::generate()?);
        let (mut run, mut prepared) = self.prepare()?;
        if let Some(build) = self.page.take() {
            run.bind_page(&self.name, build, &mut prepared).await?;
        }
        let backends = std::mem::take(&mut prepared.backends);
        let result = async {
            let ca = run.start_world(self.world, prepared).await?;
            let ca = ca.as_ref().map(|(name, pem)| (name.as_str(), pem.as_str()));
            let image = downloads.join("ubuntu-24.04-server-cloudimg-amd64.img");
            run.provision(&image, &identity.authorized_key, ca)?;
            run.start_guests(downloads, backends)?;
            run.connect_guests(identity).await
        }
        .await;
        match result {
            Ok(()) => Ok(run),
            Err(error) => {
                let _ = run.shutdown().await;
                Err(error)
            }
        }
    }
}

impl Run {
    async fn bind_page(
        &mut self,
        name: &str,
        build: PageBuilder,
        prepared: &mut Prepared,
    ) -> io::Result<()> {
        let observer = DashboardObserver::new(DashboardOptions {
            collector: fictionet_observe::Options::default(),
            ..Default::default()
        });
        let dashboard = observer.handle();
        prepared.observers.push(observer.observer());
        let mut hosts = Hosts(
            self.guests
                .iter()
                .map(|g| (g.name().to_string(), Some(g.console.clone())))
                .collect(),
        );
        let labels = Labels::default();
        let page = build(dashboard.clone(), &mut hosts)
            .containment(self.containment.clone())
            .labels(labels.clone())
            .console_address(jump::JUMP_ADDR.into());
        self.page = Some(page.bind_loopback(0).await.map_err(|error| {
            let text = error.to_string();
            if text == "labels called twice" || text.contains("(\"Containment\")") {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{text}; Kit::page adds containment and labels; remove any \
                         Page::containment or Page::labels calls from its builder"
                    ),
                )
            } else {
                error
            }
        })?);
        self.dashboard = Some(dashboard);
        self.labels = Some(labels);
        println!("{name} page: {}", self.page_url());
        Ok(())
    }

    async fn start_world<W, F>(
        &mut self,
        start: W,
        prepared: Prepared,
    ) -> io::Result<Option<(String, String)>>
    where
        W: FnOnce(Cx, World) -> F + Send + 'static,
        F: Future<Output = fictionet::Result> + Send + 'static,
    {
        let ca = Arc::new(Mutex::new(None));
        let world = World {
            attachments: prepared.attachments,
            ca: ca.clone(),
            mirror: None,
            now_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs() as i64,
        };
        let fcx_slot = self.fcx.clone();
        let (ready, receive) = oneshot::channel();
        let (bridge_tx, bridge_rx) = oneshot::channel();
        let options =
            RunOptions::new(Seed::random()).observer(Arc::new(Fanout::new(prepared.observers)));
        let labels = self.labels.clone();
        let consoles: Vec<_> = self
            .guests
            .iter()
            .map(|g| (g.console.clone(), g.addr()))
            .collect();
        self.world = Some(tokio::spawn(fictionet::run(
            options,
            move |fcx| async move {
                *fcx_slot.lock().unwrap() = Some(fcx.clone());
                for (console, address) in consoles {
                    console.booting(&fcx);
                    if let Some(address) = address {
                        console.network(&fcx, address);
                    }
                }
                if let Some(labels) = labels {
                    fcx.spawn(move |cx| async move {
                        labels.run(&cx).await?;
                        Ok(())
                    });
                }
                let jump = jump::Jump::new(&fcx, prepared.jump_link);
                let tasks = prepared
                    .bridges
                    .into_iter()
                    .map(|b| {
                        tokio::spawn(bridge::run(
                            b.frames,
                            b.queue,
                            b.link,
                            fcx.clone(),
                            b.family,
                        ))
                    })
                    .collect::<Vec<_>>();
                let _ = bridge_tx.send(tasks);
                let result = start(fcx, world).await;
                let _ = ready.send(result.as_ref().map(|_| jump).map_err(|e| e.to_string()));
                result
            },
        )));
        self.bridges = bridge_rx.await.map_err(io::Error::other)?;
        let jump = receive
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        self.jump = Some(Arc::new(jump));
        Ok(ca.lock().unwrap().clone())
    }

    fn provision(&self, image: &Path, key: &str, ca: Option<(&str, &str)>) -> io::Result<()> {
        let image = std::fs::canonicalize(image)?;
        for guest in &self.guests {
            let r = &guest.resources;
            std::fs::write(
                &r.seed,
                seed::build(&seed::Provision {
                    guest: &guest.guest,
                    authorized_key: key,
                    ca,
                })?,
            )?;
            vm::disk::write_overlay(&r.overlay, &image, 10 << 30)?;
        }
        Ok(())
    }

    fn start_guests(&mut self, downloads: &Path, backends: Vec<BackendInput>) -> io::Result<()> {
        self.boot = Instant::now();
        for (guest, (tx, queue)) in self.guests.iter_mut().zip(backends) {
            let r = &guest.resources;
            guest.backend = Some(net::start(&r.socket, r.mac, tx, queue)?);
            let mac = r.mac.map(|b| format!("{b:02x}")).join(":");
            let config = vm::Config {
                cloud_hypervisor: &downloads.join("cloud-hypervisor"),
                vmlinuz: &downloads.join("ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic"),
                initrd: &downloads.join("ubuntu-24.04-server-cloudimg-amd64-initrd-generic"),
                cmdline: "root=LABEL=cloudimg-rootfs ro console=ttyS0,115200n8 net.ifnames=0",
                overlay: &r.overlay,
                seed: &r.seed,
                net_socket: &r.socket,
                mac: &mac,
                vcpus: guest.guest.vcpus,
                memory_mib: guest.guest.memory_mib,
                manufacturer: &guest.guest.manufacturer,
                product: &guest.guest.product,
                uuid: &r.uuid,
            };
            let vm = vm::Vm::start(&config, &r.dir)
                .map_err(|e| io::Error::other(format!("{}: {e}", guest.name())))?;
            guest.vm = Some(vm);
        }
        Ok(())
    }

    async fn connect_guests(&mut self, identity: Arc<ssh::Identity>) -> io::Result<()> {
        let mut sessions = JoinSet::new();
        for (index, guest) in self.guests.iter().enumerate() {
            let jump = self.jump.as_ref().expect("world started").clone();
            let identity = identity.clone();
            let addr = guest.addr.clone();
            let user = guest.guest.user.clone();
            let console = guest.console.clone();
            let cx = self.fcx.lock().unwrap().as_ref().unwrap().clone();
            sessions.spawn(async move {
                {
                    let mut address = addr.clone();
                    match tokio::time::timeout(
                        Duration::from_secs(300),
                        address.wait_for(Option::is_some),
                    )
                    .await
                    {
                        Ok(Ok(address)) => console.network(&cx, address.unwrap()),
                        Ok(Err(error)) => return (index, Err(io::Error::other(error))),
                        Err(_) => {
                            return (
                                index,
                                Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "guest address was not assigned within 300 seconds",
                                )),
                            );
                        }
                    }
                }
                let session = ssh::Session::connect(
                    || jump.connect_addr(addr.clone(), 22, Duration::from_secs(10)),
                    &identity,
                    &user,
                    Duration::from_secs(300),
                )
                .await;
                (index, session)
            });
        }
        while let Some(result) = sessions.join_next().await {
            let (index, result) = result.map_err(io::Error::other)?;
            let guest = &mut self.guests[index];
            let session = result.map_err(|e| {
                io::Error::other(format!(
                    "{}: {e}\n--- cloud-hypervisor stderr ---\n{}\n--- guest console tail ---\n{}",
                    guest.name(),
                    guest.vm().ch_stderr_tail(),
                    guest.vm().console_tail()
                ))
            })?;
            self.connected(index, Arc::new(session));
        }
        Ok(())
    }

    fn connected(&mut self, index: usize, session: Arc<ssh::Session>) {
        let guest = &mut self.guests[index];
        guest.ssh = Some(session);
        guest.boot = self.boot;
        guest.ssh_ready = self.boot.elapsed();
        let cx = self.fcx.lock().unwrap().as_ref().unwrap().clone();
        let session = guest.ssh().clone();
        guest
            .console
            .connected(&cx, session.clone(), guest.addr().unwrap(), self.boot);
        if let Some(dashboard) = self.dashboard.clone() {
            let name = guest.guest.attachment.clone();
            let topic = self.containment.clone();
            let probes = self.probes.clone();
            cx.spawn(move |cx| async move {
                let Ok(result) = cx
                    .race(None, containment::run(&session, &name, &dashboard))
                    .await
                else {
                    return Ok(());
                };
                let mut all = probes.lock().unwrap();
                all.probes.extend(result.probes);
                if let Err(error) = topic.publish(cx.now(), &all) {
                    eprintln!("containment: {error}");
                }
                Ok(())
            });
        }
    }
}

#[cfg(test)]
mod tests;
