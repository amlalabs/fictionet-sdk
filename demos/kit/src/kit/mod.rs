//! Guest provisioning, networking and process lifetime. Each app owns its page.
pub mod bridge;
pub mod desktop;
pub mod image;
pub mod jump;
pub mod mirror;
pub mod net;
pub mod page;
pub mod preview;
pub mod seed;
pub mod shot;
pub mod ssh;
mod util;
pub mod vm;
use fictionet::stdlib::network::ethernet::Family;
use fictionet::{Attachments, Cx, Seed};
pub use page::{PAGE_PORT, PageAccess};
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
pub use util::{RunDir, random_uuid};
/// The admin attachment and route.
pub const JUMP: &str = "jump";
/// The account a prepared image keeps for the host's own control: key login
/// only, with sudo and no password.
pub const ADMIN: &str = "ops";
/// The largest IP packet a guest's card carries.
const MTU: u16 = 1500;
/// The route prefix for the admin jump host.
pub fn jump_prefix() -> fictionet::stdlib::network::route::Prefix {
    fictionet::stdlib::network::route::Prefix {
        addr: jump::JUMP_ADDR.into(),
        len: 32,
    }
}

#[derive(Clone)]
struct File {
    path: String,
    mode: u32,
    content: String,
}

/// Software installed by the guest's setup pieces.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Features {
    /// Claude Code is installed.
    pub claude_code: bool,
    /// Codex is installed.
    pub codex: bool,
    /// Firefox is installed.
    pub firefox: bool,
}

/// Software installed while provisioning an Ubuntu cloud guest.
#[derive(Clone, Default)]
pub struct Installation {
    files: Vec<File>,
    packages: Vec<String>,
    steps: Vec<String>,
}

/// An existing image; runtime settings cannot add installation steps.
#[derive(Clone)]
pub struct PreparedImage(String);

/// The provisioning data needed to boot a guest.
pub trait Software: Clone {
    fn image(&self) -> Option<&str>;
    fn installation(&self) -> Option<&Installation>;
}
impl Software for Installation {
    fn image(&self) -> Option<&str> {
        None
    }
    fn installation(&self) -> Option<&Installation> {
        Some(self)
    }
}
impl Software for PreparedImage {
    fn image(&self) -> Option<&str> {
        Some(&self.0)
    }
    fn installation(&self) -> Option<&Installation> {
        None
    }
}

#[derive(Clone)]
pub enum Boot {
    Cloud(Installation),
    Prepared(PreparedImage),
}
impl Software for Boot {
    fn image(&self) -> Option<&str> {
        match self {
            Self::Cloud(_) => None,
            Self::Prepared(image) => image.image(),
        }
    }
    fn installation(&self) -> Option<&Installation> {
        match self {
            Self::Cloud(installation) => Some(installation),
            Self::Prepared(_) => None,
        }
    }
}

/// A guest's identity, resources, card, and provisioning.
#[derive(Clone)]
pub struct Guest<P = Installation> {
    /// Software installed by this guest's setup.
    pub features: Features,
    software: P,
    hostname: String,
    attachment: String,
    user: String,
    vcpus: u8,
    memory_mib: u32,
    manufacturer: String,
    product: String,
    family: Family<Ipv4Addr>,
    desktop: Option<(u16, String)>,
    terminal: Option<String>,
    forbidden: Vec<String>,
}

impl<P: Software> Guest<P> {
    /// Creates an Ubuntu guest with 2 vCPUs, 2048 MiB, and `Family::FromWorld`.
    /// DMI defaults to manufacturer `LENOVO` and product `20UES000-WS`.
    fn base(hostname: &str, user: &str, software: P) -> Self {
        Self {
            software,
            features: Features::default(),
            hostname: hostname.into(),
            attachment: hostname.into(),
            user: user.into(),
            vcpus: 2,
            memory_mib: 2048,
            manufacturer: "LENOVO".into(),
            product: "20UES000-WS".into(),
            family: Family::FromWorld,
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
    /// Declares a loopback VNC port and a command, run as the guest's user,
    /// that exits zero when the desktop is ready.
    pub fn desktop(mut self, port: u16, ready: impl Into<String>) -> Self {
        self.desktop = Some((port, ready.into()));
        self
    }
    /// Runs a command as the guest's user on the page terminal's PTY instead
    /// of a login shell.
    pub fn terminal(mut self, command: impl Into<String>) -> Self {
        self.terminal = Some(command.into());
        self
    }
    /// The account the host logs in as: a prepared image's admin, or a cloud
    /// guest's own user.
    fn login(&self) -> &str {
        match self.software.image() {
            Some(_) => ADMIN,
            None => &self.user,
        }
    }
    /// `command` as run by the guest's user from the host's login.
    fn as_user(&self, command: &str) -> String {
        if self.login() == self.user {
            command.into()
        } else {
            format!("sudo -u {} sh -c {}", self.user, ssh::quote(command))
        }
    }
    /// What the page terminal runs, as the guest's user: its declared
    /// command, else the user's login shell.
    fn terminal_command(&self) -> Option<String> {
        match &self.terminal {
            Some(command) => Some(self.as_user(command)),
            None if self.login() == self.user => None,
            None => Some(format!("sudo -u {} -i", self.user)),
        }
    }
    /// Adds words that nothing in this guest may contain, beside the shared guest vocabulary.
    pub fn forbid(mut self, words: &[&str]) -> Self {
        self.forbidden
            .extend(words.iter().map(|w| w.to_ascii_lowercase()));
        self
    }
    /// Returns the first word of the shared guest vocabulary or [`Guest::forbid`] that
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
        if let Some(image) = self.software.image()
            && !matches!(
                Path::new(image).components().collect::<Vec<_>>().as_slice(),
                [std::path::Component::Normal(_)]
            )
        {
            return Err(io::Error::other(
                "prepared image must be a file in the downloads directory",
            ));
        }
        let texts = [
            ("DMI string", &self.manufacturer),
            ("DMI string", &self.product),
        ]
        .into_iter()
        .chain(
            self.software
                .installation()
                .into_iter()
                .flat_map(|i| i.files.iter())
                .flat_map(|f| [("file path", &f.path), ("file", &f.content)]),
        )
        .chain(
            self.software
                .installation()
                .into_iter()
                .flat_map(|i| i.packages.iter())
                .map(|p| ("package", p)),
        )
        .chain(
            self.software
                .installation()
                .into_iter()
                .flat_map(|i| i.steps.iter())
                .map(|s| ("command", s)),
        )
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

impl Guest<Installation> {
    /// An Ubuntu guest with background refreshes disabled: a cloud guest
    /// provisioned on its first boot, or the recipe of a prepared image.
    /// A cloud guest also keeps the host's clock (see [`seed::build`]).
    pub fn ubuntu(hostname: &str, user: &str) -> Self {
        let mut guest = Self::base(hostname, user, Installation::default());
        guest = guest
            // The Pro apt hook contacts the contract service during package setup.
            .file("/etc/apt/apt.conf.d/20apt-esm-hook.conf", 0o644, "")
            // Pro apt news fetches a remote news feed during package setup.
            .file(
                "/etc/ubuntu-advantage/uaclient.conf",
                0o644,
                "ua_config:\n  apt_news: false\n",
            )
            // Release checks fetch the upgrade list even when no upgrade is wanted.
            .file(
                "/etc/update-manager/release-upgrades",
                0o644,
                "[DEFAULT]\nPrompt=never\n",
            )
            // Stop unattended apt work after cloud-init's explicit package setup.
            .file(
                "/etc/apt/apt.conf.d/99periodic",
                0o644,
                "APT::Periodic::Enable \"0\";\n",
            )
            // Login messages do not need remote news.
            .file("/etc/default/motd-news", 0o644, "ENABLED=0\n");
        // Prevent later refresh starts when desktop setup reloads systemd.
        for unit in [
            "snapd.socket",
            "snapd.service",
            "snapd.seeded.service",
            "motd-news.service",
            "motd-news.timer",
            "ua-timer.timer",
            "ua-timer.service",
            "ubuntu-advantage.service",
            "fwupd-refresh.service",
            "fwupd-refresh.timer",
            "apt-daily.timer",
            "apt-daily.service",
            "apt-daily-upgrade.timer",
            "apt-daily-upgrade.service",
        ] {
            guest = guest
                .file(
                    &format!("/etc/systemd/system/{unit}.d/quiet.conf"),
                    0o644,
                    "[Unit]\nConditionPathExists=/etc/office-refresh-enabled\n",
                )
                // Stop any refresh job that was already active before provisioning.
                .run(format!(
                    "if systemctl is-active --quiet {unit}; then systemctl stop {unit}; fi"
                ));
        }
        guest
    }

    /// Adds a file with Unix permission bits and UTF-8 content.
    pub fn file(mut self, path: &str, mode: u32, content: impl Into<String>) -> Self {
        self.software.files.retain(|file| file.path != path);
        self.software.files.push(File {
            path: path.into(),
            mode,
            content: content.into(),
        });
        self
    }
    /// Installs a named root certificate in an image's system trust store,
    /// which Firefox reads through p11-kit. The name must contain only
    /// neutral ASCII letters, digits, hyphens, or underscores.
    pub fn trust(self, name: &str, pem: &str) -> io::Result<Self> {
        if !valid_name(name) {
            return Err(io::Error::other("invalid root certificate name"));
        }
        Ok(self
            .file(
                &format!("/usr/local/share/ca-certificates/{name}.crt"),
                0o644,
                pem,
            )
            .run("update-ca-certificates"))
    }
    /// Adds packages to install after the shared trust store is ready.
    pub fn packages(mut self, packages: &[&str]) -> Self {
        self.software
            .packages
            .extend(packages.iter().map(|s| s.to_string()));
        self
    }
    /// Appends a shell command to run after package installation.
    pub fn run(mut self, command: impl Into<String>) -> Self {
        self.software.steps.push(command.into());
        self
    }
    /// Puts a shell command before every other step, still after package
    /// installation: before the desktop starts, for one.
    pub fn run_first(mut self, command: impl Into<String>) -> Self {
        self.software.steps.insert(0, command.into());
        self
    }

    /// Takes the installation recipe without runtime network or resource
    /// settings, with an [`ADMIN`] account that accepts `admin`.
    pub fn into_recipe(self, admin: &ssh::Identity) -> io::Result<image::Recipe> {
        self.validate()?;
        Ok(image::Recipe {
            hostname: self.hostname,
            user: self.user,
            admin_key: admin.authorized_key.clone(),
            files: self.software.files,
            packages: self
                .software
                .packages
                .into_iter()
                .map(image::Package::Repository)
                .collect(),
            steps: self.software.steps,
        })
    }
}

impl Guest<PreparedImage> {
    /// A guest whose software, settings and keys are already in its image,
    /// built with [`Guest::into_recipe`]. The host logs in as [`ADMIN`] with
    /// the key the build left beside the image.
    ///
    /// ```compile_fail
    /// use fictionet_demo::kit::Guest;
    /// Guest::prepared("station", "analyst", "desktop.qcow2").packages(&["curl"]);
    /// ```
    pub fn prepared(hostname: &str, user: &str, image: &str) -> Self {
        Self::base(hostname, user, PreparedImage(image.into()))
    }
}

impl From<Installation> for Boot {
    fn from(value: Installation) -> Self {
        Self::Cloud(value)
    }
}
impl From<PreparedImage> for Boot {
    fn from(value: PreparedImage) -> Self {
        Self::Prepared(value)
    }
}

impl<P: Software + Into<Boot>> Guest<P> {
    fn into_boot(self) -> Guest<Boot> {
        Guest {
            software: self.software.into(),
            features: self.features,
            hostname: self.hostname,
            attachment: self.attachment,
            user: self.user,
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            manufacturer: self.manufacturer,
            product: self.product,
            family: self.family,
            desktop: self.desktop,
            terminal: self.terminal,
            forbidden: self.forbidden,
        }
    }
}

fn valid_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && fictionet_extras::guest_content::forbidden_installation_word(&lower).is_none()
}

/// The first word of the shared guest vocabulary or `extra` in `text`, ignoring case.
fn forbidden_in<'a>(text: &str, extra: &'a [String]) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    fictionet_extras::guest_content::forbidden_installation_word(text).or_else(|| {
        extra
            .iter()
            .map(String::as_str)
            .find(|word| lower.contains(word))
    })
}

/// Inputs available to a world author before any guest boots.
pub struct World {
    attachments: Attachments,
    ca: Arc<Mutex<Option<(String, String)>>>,
    now_unix: i64,
    mirror: Arc<Mutex<Option<mirror::Mirror<fictionet::stdlib::web::Proxy>>>>,
    setup: Arc<std::sync::atomic::AtomicBool>,
}

impl World {
    /// Returns the run start time as Unix seconds for certificate issuance.
    pub fn now_unix(&self) -> i64 {
        self.now_unix
    }
    /// Installs a named root certificate in each cloud guest's system trust
    /// store; a prepared image trusts what its recipe did ([`Guest::trust`]).
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
    ) -> fictionet::Result<mirror::Mirror<fictionet::stdlib::web::Proxy>> {
        let mut mirror = self.mirror.lock().unwrap();
        if mirror.is_none() {
            let mut cache = mirror::new(fcx)?;
            cache.closed = self.setup.clone();
            *mirror = Some(cache);
        }
        Ok(mirror.as_ref().unwrap().clone())
    }
    /// Returns the guest and jump host attachments for the world to serve.
    pub fn into_attachments(self) -> Attachments {
        self.attachments
    }
}

struct Resources {
    dir: PathBuf,
    socket: PathBuf,
    _socket_dir: std::fs::File,
    overlay: PathBuf,
    seed: PathBuf,
    mac: [u8; 6],
    uuid: String,
}

impl Resources {
    fn new<P: Software>(root: &Path, guest: &Guest<P>) -> io::Result<Self> {
        let dir = root.join(&guest.hostname);
        std::fs::create_dir(&dir)?;
        let hash = crc32fast::hash(guest.hostname.as_bytes()).to_be_bytes();
        let mut device = [hash[1], hash[2], hash[3]];
        for i in 0..2 {
            if device[i..i + 2] == [0x66, 0x6e] {
                device[i + 1] = 0x6f;
            }
        }
        let socket_dir = std::fs::File::open(&dir)?;
        Ok(Self {
            socket: util::socket_path(&socket_dir, "net.sock"),
            _socket_dir: socket_dir,
            overlay: dir.join("overlay.qcow2"),
            seed: dir.join("seed.img"),
            dir,
            mac: [0xe4, 0xc7, 0x67, device[0], device[1], device[2]],
            uuid: random_uuid(),
        })
    }
}

/// A running guest reached through the admin's SSH session.
pub struct GuestHandle {
    guest: Guest<Boot>,
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
    /// The console and status for the app's own routes.
    pub fn console(&self) -> page::GuestConsole {
        self.console.clone()
    }
    /// Returns the SSH session connected through the jump host.
    pub fn ssh(&self) -> &Arc<ssh::Session> {
        self.ssh.as_ref().expect("boot completed")
    }
    /// Returns the guest process and its diagnostics.
    pub fn vm(&self) -> &vm::Vm {
        self.vm.as_ref().expect("boot completed")
    }
    /// Waits up to timeout for the guest's desktop, even before an app opens its page.
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
    ownership: Option<vm::Ownership>,
    guests: Vec<GuestHandle>,
    fcx: Arc<Mutex<Option<Cx>>>,
    world: Option<JoinHandle<fictionet::Result>>,
    jump: Option<Arc<jump::Jump>>,
    bridges: Vec<JoinHandle<()>>,
    dir: Option<util::RunDir>,
    boot: Instant,
    setup: Arc<std::sync::atomic::AtomicBool>,
    mirror: Arc<Mutex<Option<mirror::Mirror<fictionet::stdlib::web::Proxy>>>>,
}

impl Run {
    /// Returns the named guest, panicking if it was not declared.
    pub fn guest(&self, name: &str) -> &GuestHandle {
        self.guests
            .iter()
            .find(|g| g.name() == name)
            .unwrap_or_else(|| panic!("guest {name} is not declared"))
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
        self.setup.store(true, std::sync::atomic::Ordering::Release);
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
        if let Some(mut world) = self.world.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut world).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => failures.push(format!("world failed: {error}")),
                Ok(Err(error)) => failures.push(format!("world task failed: {error}")),
                Err(_) => {
                    world.abort();
                    let _ = world.await;
                    failures.push("world did not stop within five seconds".into());
                }
            }
        }
        self.mirror.lock().unwrap().take();
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
    /// Waits until `host` shows its desktop and every cloud guest has
    /// finished cloud-init. The package mirror stops forwarding setup traffic
    /// when this returns, ready or not, or when it is dropped unfinished.
    pub async fn app_ready(&self, host: &str) -> io::Result<()> {
        struct CloseSetup<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for CloseSetup<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        let _close = CloseSetup(&self.setup);
        let desktop = self
            .guest(host)
            .wait_desktop(Duration::from_secs(300))
            .await?;
        println!("desktop up: {} ms", desktop.as_millis());
        for guest in &self.guests {
            if guest.guest.software.installation().is_some() {
                let setup = guest.wait_cloud_init(Duration::from_secs(300)).await?;
                println!("{} ready: {} ms", guest.name(), setup.as_millis());
            }
        }
        Ok(())
    }

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

type BackendInput = (tokio::sync::mpsc::Sender<Vec<u8>>, net::RxQueue);

struct Bridge {
    frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
    queue: net::RxQueue,
    link: fictionet::End,
    family: Family<Ipv4Addr>,
    address: watch::Sender<Option<Ipv4Addr>>,
}

struct Prepared {
    attachments: Attachments,
    jump_link: fictionet::End,
    bridges: Vec<Bridge>,
    backends: Vec<BackendInput>,
}

fn check_downloads<P: Software>(downloads: &Path, guests: &[Guest<P>]) -> io::Result<()> {
    for file in [
        "cloud-hypervisor",
        "ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic",
        "ubuntu-24.04-server-cloudimg-amd64-initrd-generic",
    ] {
        if !downloads.join(file).is_file() {
            return Err(io::Error::other(format!(
                "missing {}",
                downloads.join(file).display()
            )));
        }
    }
    for guest in guests {
        let files = match guest.software.image() {
            Some(name) => {
                let baked = image::Baked::new(downloads, name);
                vec![baked.image().to_owned(), baked.admin_key()]
            }
            None => vec![downloads.join("ubuntu-24.04-server-cloudimg-amd64.img")],
        };
        for file in files {
            if !file.is_file() {
                return Err(io::Error::other(format!(
                    "missing {}; build it with cargo xtask search-image <downloads>",
                    file.display()
                )));
            }
        }
    }
    Ok(())
}

fn prepare<P: Software + Into<Boot>>(
    name: &str,
    guests: Vec<Guest<P>>,
) -> io::Result<(Run, Prepared)> {
    if guests.is_empty() {
        return Err(io::Error::other("declare at least one guest"));
    }
    let mut names = std::collections::HashSet::new();
    let mut attachments = std::collections::HashSet::new();
    for guest in &guests {
        guest.validate()?;
        if !names.insert(&guest.hostname) || !attachments.insert(&guest.attachment) {
            return Err(io::Error::other("duplicate guest hostname or attachment"));
        }
    }
    let setup = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut run = Run {
        ownership: None,
        guests: Vec::new(),
        setup: setup.clone(),
        mirror: Arc::default(),
        fcx: Arc::new(Mutex::new(None)),
        world: None,
        jump: None,
        bridges: Vec::new(),
        dir: Some(util::RunDir::new(&std::env::temp_dir(), name)?),
        boot: Instant::now(),
    };
    let (attacher, attachments) = fictionet::attachments();
    let mut prepared = Prepared {
        attachments,
        jump_link: attacher.attach(JUMP).map_err(io::Error::other)?,
        bridges: Vec::new(),
        backends: Vec::new(),
    };
    for guest in guests.into_iter().map(Guest::into_boot) {
        let resources = Resources::new(run.path(), &guest)?;
        let link = attacher
            .attach(&guest.attachment)
            .map_err(io::Error::other)?;
        let (tx, frames) = tokio::sync::mpsc::channel(net::QUEUE_LIMIT);
        let queue = net::RxQueue::new()?;
        prepared.backends.push((tx, queue.clone()));
        let (tx_addr, addr) = watch::channel(guest.initial_addr());
        prepared.bridges.push(Bridge {
            frames,
            queue,
            link,
            family: guest.family.clone(),
            address: tx_addr,
        });
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

/// Boots guests after the app has connected their consoles to its own page.
pub async fn boot<W, F, P: Software + Into<Boot>>(
    name: &str,
    guests: Vec<Guest<P>>,
    downloads: impl AsRef<Path>,
    ready: impl FnOnce(Vec<page::GuestConsole>),
    start: W,
) -> io::Result<Run>
where
    W: FnOnce(Cx, World) -> F + Send + 'static,
    F: Future<Output = fictionet::Result> + Send + 'static,
{
    let downloads = downloads.as_ref();
    let ownership = vm::Ownership::acquire(name)?;
    check_downloads(downloads, &guests)?;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|error| io::Error::other(format!("/dev/kvm is not usable: {error}")))?;
    let (mut run, mut prepared) = prepare(name, guests)?;
    run.ownership = Some(ownership);
    ready(run.guests.iter().map(GuestHandle::console).collect());
    let backends = std::mem::take(&mut prepared.backends);
    let result = async {
        let ca = run.start_world(start, prepared).await?;
        let ca = ca.as_ref().map(|(name, pem)| (name.as_str(), pem.as_str()));
        let identities = run.provision(downloads, ca)?;
        run.start_guests(downloads, backends)?;
        run.connect_guests(identities).await
    }
    .await;
    match result {
        Ok(()) => Ok(run),
        Err(error) => {
            for guest in run.guests() {
                eprint!("{}", guest.diagnostics().await);
            }
            let _ = run.shutdown().await;
            Err(error)
        }
    }
}

impl Run {
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
            setup: self.setup.clone(),
            attachments: prepared.attachments,
            ca: ca.clone(),
            mirror: self.mirror.clone(),
            now_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs() as i64,
        };
        let fcx_slot = self.fcx.clone();
        let (ready, receive) = oneshot::channel();
        let (bridge_tx, bridge_rx) = oneshot::channel();
        let options = Seed::random();
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
                    console.booting(&fcx, address);
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
                            b.address,
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

    /// Writes each guest's overlay, and a cloud guest's seed with a key made
    /// for this run. Returns the identity the host logs in to each guest with.
    fn provision(
        &self,
        downloads: &Path,
        ca: Option<(&str, &str)>,
    ) -> io::Result<Vec<Arc<ssh::Identity>>> {
        let cloud = self
            .guests
            .iter()
            .any(|guest| guest.guest.software.installation().is_some())
            .then(ssh::Identity::generate)
            .transpose()?
            .map(Arc::new);
        let mut identities = Vec::new();
        for guest in &self.guests {
            let r = &guest.resources;
            let (image, identity) = match guest.guest.software.image() {
                Some(name) => {
                    let baked = image::Baked::new(downloads, name);
                    let identity = Arc::new(ssh::Identity::read(&baked.admin_key())?);
                    (baked.image().to_owned(), identity)
                }
                None => {
                    let identity = cloud.clone().expect("made for cloud guests");
                    std::fs::write(
                        &r.seed,
                        seed::build(&seed::Provision {
                            guest: &guest.guest,
                            authorized_key: &identity.authorized_key,
                            ca,
                        })?,
                    )?;
                    (
                        downloads.join("ubuntu-24.04-server-cloudimg-amd64.img"),
                        identity,
                    )
                }
            };
            vm::disk::write_overlay(&r.overlay, &std::fs::canonicalize(image)?, 10 << 30)?;
            identities.push(identity);
        }
        Ok(identities)
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
                seed: guest
                    .guest
                    .software
                    .installation()
                    .map(|_| r.seed.as_path()),
                net_socket: &r.socket,
                mac: &mac,
                vcpus: guest.guest.vcpus,
                memory_mib: guest.guest.memory_mib,
                manufacturer: &guest.guest.manufacturer,
                product: &guest.guest.product,
                uuid: &r.uuid,
            };
            let vm = vm::Vm::start(&config, &r.dir, self.ownership.as_ref().expect("owned run"))
                .map_err(|e| io::Error::other(format!("{}: {e}", guest.name())))?;
            guest.vm = Some(vm);
        }
        Ok(())
    }

    async fn connect_guests(&mut self, identities: Vec<Arc<ssh::Identity>>) -> io::Result<()> {
        let mut sessions = JoinSet::new();
        for ((index, guest), identity) in self.guests.iter().enumerate().zip(identities) {
            let jump = self.jump.as_ref().expect("world started").clone();
            let addr = guest.addr.clone();
            let user = guest.guest.login().to_owned();
            let console = guest.console.clone();
            let configured = guest.guest.initial_addr().is_some();
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
                        Ok(Ok(address)) => {
                            if !configured {
                                console.network(&cx, address.unwrap());
                            }
                        }
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
        let mut exited = tokio::time::interval(Duration::from_millis(50));
        while !sessions.is_empty() {
            let result = tokio::select! {
                result = sessions.join_next() => result.expect("pending guest session"),
                _ = exited.tick() => {
                    for guest in &mut self.guests {
                        if let Some(status) = guest.vm.as_mut().expect("started").exited()? {
                            let message = format!("{}: Cloud Hypervisor exited with {status}\n{}\n{}",
                                guest.name(), guest.vm().ch_stderr_tail(), guest.vm().console_tail());
                            guest.console.failed(self.fcx.lock().unwrap().as_ref().unwrap(), &message);
                            return Err(io::Error::other(message));
                        }
                    }
                    continue;
                }
            };
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
    }
}
impl GuestHandle {
    /// Waits for cloud-init and returns time since boot. Nonzero status fails
    /// with its report, bounded to 64 KiB.
    pub async fn wait_cloud_init(&self, timeout: Duration) -> io::Result<Duration> {
        let output = tokio::time::timeout(
            timeout,
            self.ssh()
                .run_bounded("sudo cloud-init status --wait --long", 64 << 10),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{}: cloud-init did not finish within {} s",
                    self.name(),
                    timeout.as_secs()
                ),
            )
        })??;
        if output.code != 0 {
            return Err(io::Error::other(format!(
                "{}: cloud-init exit {}\n{}{}",
                self.name(),
                output.code,
                output.stdout,
                output.stderr
            )));
        }
        Ok(self.boot.elapsed())
    }

    /// The guest's side of a failed run, for a demo to print: cloud-init's
    /// report and log tail, the desktop's state and logs when the guest has
    /// one, and the serial console tail. Each command has 3 s and 16 KiB.
    pub async fn diagnostics(&self) -> String {
        let mut out = format!("--- {} diagnostics ---\n", self.name());
        match &self.ssh {
            None => out.push_str("No SSH session; only the console tail is available.\n"),
            Some(ssh) => {
                let desktop = self.guest.desktop.is_some().then_some(DESKTOP_DIAGNOSTICS);
                let commands = DIAGNOSTICS.iter().map(|command| command.to_string()).chain(
                    desktop
                        .into_iter()
                        .flatten()
                        .map(|command| self.guest.as_user(command)),
                );
                for command in commands {
                    let result = tokio::time::timeout(
                        DIAGNOSTIC_TIMEOUT,
                        ssh.run_bounded(&command, DIAGNOSTIC_BYTES),
                    )
                    .await;
                    out.push_str(&match result {
                        Ok(Ok(output)) => format!(
                            "guest$ {command}\n{}{}[exit {}]\n",
                            output.stdout, output.stderr, output.code
                        ),
                        Ok(Err(error)) => format!("guest$ {command}\nunavailable: {error}\n"),
                        Err(_) => format!("guest$ {command}\ntimed out\n"),
                    });
                }
            }
        }
        if let Some(vm) = &self.vm {
            out.push_str(&format!(
                "--- {} console tail ---\n{}\n",
                self.name(),
                vm.console_tail()
            ));
        }
        out
    }
}

const DIAGNOSTICS: &[&str] = &[
    "cloud-init status --long",
    "sudo tail -n 30 /var/log/cloud-init-output.log",
];
/// The commands it adds for a guest with a desktop.
const DESKTOP_DIAGNOSTICS: &[&str] = &[
    "systemctl is-active vnc",
    "tail -n 15 /tmp/xvnc.log /tmp/xfce.log",
    "tail -n 40 /tmp/firefox.log",
    desktop::FIREFOX_TITLE,
];
/// Each diagnostic command's time and output bounds.
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(3);
const DIAGNOSTIC_BYTES: usize = 16 << 10;

#[cfg(test)]
mod tests;
