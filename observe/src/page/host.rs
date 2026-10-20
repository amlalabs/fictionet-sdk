use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{StateLimits, StateTopic};

/// An executor-owned asynchronous operation.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bidirectional console byte stream.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A terminal channel. Dropping it must close the underlying channel too.
pub trait Pty: Send {
    /// Reads one chunk, applying backpressure. Cancellation must not lose bytes.
    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<Vec<u8>>>>;
    /// Writes input bytes.
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
    /// Changes the terminal dimensions.
    fn resize(&self, cols: u16, rows: u16) -> BoxFuture<'_, io::Result<()>>;
    /// Closes the terminal channel.
    fn close(&self) -> BoxFuture<'_, io::Result<()>>;
}

/// Host console capabilities, independent of any VM or SSH implementation.
/// Methods return lazy futures: opening must happen only when polled.
/// Returning Some declares a capability even while the host is booting;
/// its future should return an error describing why the host is not ready.
pub trait Console: Send + Sync + 'static {
    /// Opens a byte stream to the VNC server, or None for no screen capability.
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>>;
    /// Opens a new shell, or None for no terminal capability.
    fn terminal(
        &self,
        cols: u16,
        rows: u16,
    ) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>>;
}

/// Host readiness, published by the owner of the machine.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    /// The machine is starting.
    #[default]
    Booting,
    /// Its network is available.
    NetworkUp,
    /// SSH is available.
    SshUp,
    /// Its desktop is available.
    DesktopUp,
    /// The machine has stopped.
    Stopped,
}

/// Live readiness and addresses for one host.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostStatus {
    /// Current readiness.
    pub state: HostState,
    /// Addresses displayed by the browser.
    pub addresses: Vec<String>,
    /// Whether a screen can be opened now.
    pub screen: bool,
    /// Whether a terminal can be opened now.
    pub terminal: bool,
}

/// One host in the page description.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostDescription {
    /// Whether this host starts pinned in the workspace.
    pub pinned: bool,
    /// Host name used by console routes.
    pub name: String,
    /// Sandbox name in the dashboard topology.
    pub sandbox: String,
    /// Status snapshot URL; append `/stream` for SSE.
    pub status: String,
    /// Screen panel ID, when offered.
    pub screen: Option<String>,
    /// Terminal panel ID, when offered.
    pub terminal: Option<String>,
}

/// One machine in a page composition.
pub struct Host {
    pinned: bool,
    pub(super) name: String,
    pub(super) sandbox: String,
    pub(super) console: Option<Arc<dyn Console>>,
    pub(super) status: StateTopic<HostStatus>,
    pub(super) screen: bool,
    pub(super) terminal: bool,
}

impl Host {
    /// Names a host. Names contain ASCII letters, digits, hyphens or underscores.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            pinned: false,
            sandbox: name.clone(),
            name,
            console: None,
            status: StateTopic::new(StateLimits::default()),
            screen: false,
            terminal: false,
        }
    }
    /// Pins this host in the initial tiled workspace.
    pub fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }
    /// Maps this host to a world sandbox.
    pub fn sandbox(mut self, name: impl Into<String>) -> Self {
        self.sandbox = name.into();
        self
    }
    /// Supplies console capabilities. Futures must open lazily when polled.
    pub fn console(mut self, console: impl Console) -> Self {
        self.console = Some(Arc::new(console));
        self
    }
    /// Supplies live status from the machine owner.
    pub fn status(mut self, topic: StateTopic<HostStatus>) -> Self {
        self.status = topic;
        self
    }
    pub(super) fn description(&self) -> HostDescription {
        HostDescription {
            pinned: self.pinned,
            name: self.name.clone(),
            sandbox: self.sandbox.clone(),
            status: format!("/api/state/host-{}", self.name),
            screen: self
                .screen
                .then(|| format!("{}-screen", super::panel::slug(&self.name))),
            terminal: self
                .terminal
                .then(|| format!("{}-terminal", super::panel::slug(&self.name))),
        }
    }
}
