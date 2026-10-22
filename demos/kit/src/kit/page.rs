//! Console pieces an app can compose into its own page routes.
use super::{Guest, ssh};
use fictionet::Cx;
use futures_util::SinkExt;
use serde::Serialize;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub trait Duplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}
pub trait Pty: Send {
    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<Vec<u8>>>>;
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
    fn resize(&self, cols: u16, rows: u16) -> BoxFuture<'_, io::Result<()>>;
    fn close(&self) -> BoxFuture<'_, io::Result<()>>;
}
pub trait Console: Send + Sync + 'static {
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>>;
    fn terminal(
        &self,
        cols: u16,
        rows: u16,
    ) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>>;
}
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    #[default]
    Booting,
    NetworkUp,
    SshUp,
    DesktopUp,
    Stopped,
    Failed,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct HostStatus {
    pub state: HostState,
    pub addresses: Vec<String>,
    pub screen: bool,
    pub terminal: bool,
}
#[derive(Clone)]
pub struct GuestConsole {
    name: String,
    desktop: Option<(u16, String)>,
    terminal: Option<String>,
    session: Arc<Mutex<SessionState>>,
    pub status: watch::Sender<HostStatus>,
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
            desktop: guest.desktop.clone(),
            terminal: guest.terminal.clone(),
            session: Arc::new(Mutex::new(SessionState::default())),
            status: watch::channel(HostStatus::default()).0,
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
        _cx: &Cx,
        state: HostState,
        addresses: Vec<String>,
        screen: bool,
        terminal: bool,
    ) {
        self.status.send_replace(HostStatus {
            state,
            addresses,
            screen,
            terminal,
        });
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

pub const PAGE_PORT: u16 = 38877;
/// Prints the page URL and opens an app window when a display is available.
pub struct PageAccess {
    _window: Option<super::shot::AppWindow>,
}
impl PageAccess {
    pub fn new(url: &str) -> io::Result<Self> {
        println!("Page: {url}");
        let window = if std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some()
        {
            match super::shot::AppWindow::open(url) {
                Ok(w) => Some(w),
                Err(e) => {
                    eprintln!("Could not open Chromium: {e}");
                    None
                }
            }
        } else {
            None
        };
        Ok(Self { _window: window })
    }
}

/// Opens one of the app's authenticated console sockets.
pub async fn upgrade(
    upgrade: axum::extract::ws::WebSocketUpgrade,
    console: Arc<dyn Console>,
    screen: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if screen {
        let Some(connect) = console.screen() else {
            return http::StatusCode::NOT_FOUND.into_response();
        };
        match connect.await {
            Ok(stream) => upgrade
                .on_upgrade(move |socket| screen_socket(socket, stream))
                .into_response(),
            Err(error) => {
                (http::StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response()
            }
        }
    } else {
        let Some(connect) = console.terminal(80, 24) else {
            return http::StatusCode::NOT_FOUND.into_response();
        };
        match connect.await {
            Ok(pty) => upgrade
                .on_upgrade(move |socket| terminal_socket(socket, pty))
                .into_response(),
            Err(error) => {
                (http::StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response()
            }
        }
    }
}

async fn screen_socket(mut socket: axum::extract::ws::WebSocket, mut stream: Box<dyn Duplex>) {
    use axum::extract::ws::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0; 64 << 10];
    loop {
        tokio::select! {
            read = stream.read(&mut buffer) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => if socket.send(Message::Binary(buffer[..n].to_vec().into())).await.is_err() { break; },
            },
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(bytes))) => if stream.write_all(&bytes).await.is_err() { break; },
                Some(Ok(Message::Ping(bytes))) => if socket.send(Message::Pong(bytes)).await.is_err() { break; },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {},
            },
        }
    }
    let _ = stream.shutdown().await;
    let _ = socket.close().await;
}

#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TerminalInput {
    Ack { bytes: usize },
    Resize { cols: u16, rows: u16 },
}

async fn terminal_socket(mut socket: axum::extract::ws::WebSocket, mut pty: Box<dyn Pty>) {
    use axum::extract::ws::Message;
    let mut outstanding = 0usize;
    loop {
        tokio::select! {
            read = pty.read(), if outstanding < 64 << 10 => match read {
                Ok(Some(bytes)) => {
                    outstanding += bytes.len();
                    if socket.send(Message::Binary(bytes.into())).await.is_err() { break; }
                },
                _ => break,
            },
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(bytes))) => if pty.write(&bytes).await.is_err() { break; },
                Some(Ok(Message::Text(text))) => match serde_json::from_str(&text) {
                    Ok(TerminalInput::Ack { bytes }) if bytes <= outstanding => outstanding -= bytes,
                    Ok(TerminalInput::Resize { cols, rows }) if cols > 0 && rows > 0 && cols <= 1000 && rows <= 1000 => {
                        if pty.resize(cols, rows).await.is_err() { break; }
                    },
                    _ => break,
                },
                Some(Ok(Message::Ping(bytes))) => if socket.send(Message::Pong(bytes)).await.is_err() { break; },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {},
            },
        }
    }
    let _ = pty.close().await;
    let _ = socket.close().await;
}

/// Browser libraries copied with the screen and terminal pieces, served locally.
pub fn libraries() -> axum::Router {
    use axum::{extract::Path, response::IntoResponse, routing::get};
    static ASSETS: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets");
    axum::Router::new().route(
        "/vendor/{*path}",
        get(|Path(path): Path<String>| async move {
            let Some(file) = ASSETS.get_file(&path) else {
                return http::StatusCode::NOT_FOUND.into_response();
            };
            let mime = if path.ends_with(".js") {
                "text/javascript"
            } else if path.ends_with(".wasm") {
                "application/wasm"
            } else {
                "text/plain"
            };
            ([(http::header::CONTENT_TYPE, mime)], file.contents()).into_response()
        }),
    )
}
