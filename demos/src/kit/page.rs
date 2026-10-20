//! Page hosts backed by the kit's admin SSH sessions, and the loop that
//! serves a page control.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fictionet::Cx;
use fictionet_observe::page::{
    BoxFuture, Command, CommandPort, Console, Duplex, Host, HostState, HostStatus, Pty, Rejected,
    StateLimits, StateTopic,
};
use serde::Serialize;
use tokio::sync::watch;

use super::{Guest, ssh};

/// Serves the page control `port` until the page closes it. `decide` makes
/// each command's reply or its rejection; its error ends the loop.
pub async fn serve_commands<C, R: Serialize>(
    cx: &Cx,
    port: &CommandPort<C, R>,
    mut decide: impl FnMut(&C) -> fictionet::Result<Result<R, Rejected>>,
) -> fictionet::Result {
    while let Some(command) = cx.race(None, port.recv()).await? {
        answer_command(cx, command, &mut decide)?;
    }
    Ok(())
}

/// Answers one page command with the reply or the rejection `decide` makes.
pub fn answer_command<C, R: Serialize>(
    cx: &Cx,
    command: Command<C, R>,
    decide: impl FnOnce(&C) -> fictionet::Result<Result<R, Rejected>>,
) -> fictionet::Result {
    match decide(&command.command)? {
        Ok(reply) => command.reply(cx, reply),
        Err(rejection) => command.reject(cx, rejection),
    }
    Ok(())
}

/// Declared guests available to a page builder. Each host can be taken once.
pub struct Hosts(pub(super) HashMap<String, Option<GuestConsole>>);

impl Hosts {
    /// Takes a declared guest's console and status topic.
    /// Panics for an unknown guest or a host already taken by the builder.
    pub fn take(&mut self, name: &str) -> Host {
        let console = self
            .0
            .get_mut(name)
            .unwrap_or_else(|| {
                panic!("guest {name} is not declared; add it with Kit::guest before Kit::page")
            })
            .take()
            .unwrap_or_else(|| {
                panic!("guest {name} was already taken; call Hosts::take only once per guest")
            });
        Host::new(name)
            .sandbox(console.attachment.clone())
            .status(console.status.clone())
            .console(console)
    }
}

#[derive(Clone)]
pub(super) struct GuestConsole {
    name: String,
    attachment: String,
    desktop: Option<(u16, String)>,
    terminal: Option<String>,
    session: Arc<Mutex<SessionState>>,
    pub(super) status: StateTopic<HostStatus>,
    ready: watch::Sender<Readiness>,
}

#[derive(Default)]
struct SessionState {
    session: Option<Arc<ssh::Session>>,
    stopped: bool,
    address: Option<std::net::Ipv4Addr>,
}

#[derive(Clone)]
enum Readiness {
    Waiting(String),
    Ready(Duration),
    Stopped,
    Failed(String),
}

impl GuestConsole {
    pub(super) fn new(guest: &Guest) -> Self {
        Self {
            name: guest.hostname.clone(),
            attachment: guest.attachment.clone(),
            desktop: guest.desktop.clone(),
            terminal: guest.terminal.clone(),
            session: Arc::new(Mutex::new(SessionState::default())),
            status: StateTopic::new(StateLimits::default()),
            ready: watch::channel(Readiness::Waiting(
                "no completed attempt; exit code unavailable; stderr: empty".into(),
            ))
            .0,
        }
    }

    fn session(&self) -> io::Result<Arc<ssh::Session>> {
        let state = self.session.lock().unwrap();
        if state.stopped {
            return Err(io::Error::other(format!("{} has stopped", self.name)));
        }
        state.session.clone().ok_or_else(|| {
            io::Error::other(format!(
                "{} is still booting; its SSH session is not up yet",
                self.name
            ))
        })
    }

    pub(super) fn booting(&self, cx: &Cx, configured: Option<std::net::Ipv4Addr>) {
        self.publish(
            cx,
            HostState::Booting,
            configured.into_iter().map(|a| a.to_string()).collect(),
            false,
            false,
        );
    }

    pub(super) fn failed(&self, cx: &Cx, message: &str) {
        let mut state = self.session.lock().unwrap();
        state.stopped = true;
        state.session.take();
        self.ready.send_replace(Readiness::Failed(message.into()));
        self.publish(cx, HostState::Failed, vec![], false, false);
    }

    pub(super) fn network(&self, cx: &Cx, addr: std::net::Ipv4Addr) {
        let mut state = self.session.lock().unwrap();
        if state.stopped || state.session.is_some() || state.address == Some(addr) {
            return;
        }
        state.address = Some(addr);
        self.publish(
            cx,
            HostState::NetworkUp,
            vec![addr.to_string()],
            false,
            false,
        );
    }

    fn publish(
        &self,
        cx: &Cx,
        state: HostState,
        addresses: Vec<String>,
        screen: bool,
        terminal: bool,
    ) {
        self.status
            .publish(
                cx.now(),
                &HostStatus {
                    state,
                    addresses,
                    screen,
                    terminal,
                },
            )
            .expect("small host status");
    }

    pub(super) fn connected(
        &self,
        cx: &Cx,
        session: Arc<ssh::Session>,
        addr: std::net::Ipv4Addr,
        boot: Instant,
    ) {
        let mut state = self.session.lock().unwrap();
        if state.stopped {
            return;
        }
        state.session = Some(session.clone());
        self.publish(cx, HostState::SshUp, vec![addr.to_string()], false, true);
        if let Some((_, command)) = self.desktop.clone() {
            let this = self.clone();
            cx.spawn(move |cx| async move {
                loop {
                    if this.session.lock().unwrap().stopped {
                        return Ok(());
                    }
                    let attempt = cx
                        .race(
                            Some(cx.now() + Duration::from_secs(5)),
                            session.run_bounded(&command, 16 << 10),
                        )
                        .await;
                    {
                        let state = this.session.lock().unwrap();
                        if state.stopped {
                            return Ok(());
                        }
                        let diagnostic = match attempt {
                            Ok(Ok(output)) if output.code == 0 => {
                                this.publish(
                                    &cx,
                                    HostState::DesktopUp,
                                    vec![addr.to_string()],
                                    true,
                                    true,
                                );
                                this.ready.send_replace(Readiness::Ready(boot.elapsed()));
                                return Ok(());
                            }
                            Ok(Ok(output)) => format!(
                                "exit code {}; stderr tail: {}",
                                output.code,
                                tail(&output.stderr)
                            ),
                            Ok(Err(error)) => {
                                format!("exit code unavailable; stderr unavailable: {error}")
                            }
                            Err(fictionet::RaceError::Deadline) => {
                                "attempt exceeded 5 seconds; exit code unavailable; stderr unavailable".into()
                            }
                            Err(fictionet::RaceError::Cancelled) => return Ok(()),
                        };
                        this.ready.send_replace(Readiness::Waiting(diagnostic));
                    }
                    cx.sleep(Duration::from_secs(1)).await?;
                }
            });
        }
    }

    pub(super) fn stopped(&self, cx: &Cx) {
        let mut state = self.session.lock().unwrap();
        if state.stopped {
            return;
        }
        state.stopped = true;
        state.session.take();
        self.publish(cx, HostState::Stopped, vec![], false, false);
        self.ready.send_replace(Readiness::Stopped);
    }

    pub(super) async fn wait_desktop(&self, timeout: Duration) -> io::Result<Duration> {
        let Some((_, command)) = &self.desktop else {
            return Err(io::Error::other(format!(
                "{} has no desktop; declare Guest::desktop(port, ready)",
                self.name
            )));
        };
        let mut ready = self.ready.subscribe();
        match tokio::time::timeout(
            timeout,
            ready.wait_for(|value| !matches!(value, Readiness::Waiting(_))),
        )
        .await
        {
            Ok(Ok(value)) => match &*value {
                Readiness::Ready(elapsed) => Ok(*elapsed),
                Readiness::Failed(message) => Err(io::Error::other(message.clone())),
                _ => Err(io::Error::other(format!("{} has stopped", self.name))),
            },
            Ok(Err(error)) => Err(io::Error::other(error)),
            Err(_) => {
                let diagnostic = match &*self.ready.borrow() {
                    Readiness::Waiting(attempt) => attempt.clone(),
                    _ => "readiness changed at the deadline".into(),
                };
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{} desktop readiness timed out after {timeout:?}; command {command:?}; last attempt: {diagnostic}",
                        self.name
                    ),
                ))
            }
        }
    }
}

fn tail(text: &str) -> String {
    text.chars()
        .rev()
        .take(1024)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

impl Console for GuestConsole {
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
        let port = self.desktop.as_ref()?.0;
        let this = self.clone();
        Some(Box::pin(async move {
            let session = this.session()?;
            Ok(Box::new(session.forward("127.0.0.1", port, 0).await?) as Box<dyn Duplex>)
        }))
    }
    fn terminal(
        &self,
        cols: u16,
        rows: u16,
    ) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
        let this = self.clone();
        Some(Box::pin(async move {
            let session = this.session()?;
            Ok(Box::new(
                session
                    .pty(
                        "xterm-256color",
                        cols.into(),
                        rows.into(),
                        this.terminal.as_deref(),
                    )
                    .await?,
            ) as Box<dyn Pty>)
        }))
    }
}

impl Pty for ssh::Pty {
    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<Vec<u8>>>> {
        Box::pin(self.read())
    }
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.write(bytes))
    }
    fn resize(&self, cols: u16, rows: u16) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(self.resize(cols.into(), rows.into()))
    }
    fn close(&self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(self.close())
    }
}

/// A private browser bootstrap, removed when its run ends.
pub struct PageAccess {
    _dir: super::util::RunDir,
}

impl PageAccess {
    /// Prints the public address and a separate action to open the authenticated page.
    pub fn new(url: &str) -> io::Result<Self> {
        let access = Self::bootstrap(url)?;
        access.print_open();
        Ok(access)
    }

    /// Opens the authenticated page in a Chromium app window, or prints how
    /// to open it where there is no display to open it on.
    pub fn open(url: &str) -> io::Result<Self> {
        let access = Self::bootstrap(url)?;
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            access.print_open();
            return Ok(access);
        }
        let launched = std::process::Command::new("chromium")
            .args(["--password-store=basic", "--use-mock-keychain"])
            .arg(format!("--app=file://{}", access.path().display()))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match launched {
            Ok(mut chromium) => {
                // Reap it whenever it exits; the run does not wait for it.
                std::thread::spawn(move || chromium.wait());
            }
            Err(error) => {
                println!("Chromium did not start: {error}");
                access.print_open();
            }
        }
        Ok(access)
    }

    fn bootstrap(url: &str) -> io::Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        super::client::PageClient::from_url(url)?;
        let dir = super::util::RunDir::new(&std::env::temp_dir(), "page")?;
        let path = dir.path().join("open.html");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        write!(
            file,
            "<!doctype html><meta http-equiv=\"refresh\" content=\"0;url={}\">",
            url.replace('&', "&amp;")
        )?;
        println!("Page: {}", url.split('#').next().unwrap());
        Ok(Self { _dir: dir })
    }

    fn path(&self) -> std::path::PathBuf {
        self._dir.path().join("open.html")
    }

    fn print_open(&self) {
        println!(
            "Open: cargo xtask demo open {}",
            super::ssh::quote(&self.path().display().to_string())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::PageAccess;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn bootstrap_is_private_and_removed_with_its_owner() {
        let token = "ab".repeat(32);
        let access = PageAccess::new(&format!("http://127.0.0.1:8080/#token={token}")).unwrap();
        let dir = access._dir.path().to_path_buf();
        let file = dir.join("open.html");
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .contains(&format!("#token={token}"))
        );
        drop(access);
        assert!(!dir.exists());
    }
}
