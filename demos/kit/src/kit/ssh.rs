//! An embedded SSH client: it reaches Ubuntu's own sshd on the guest's port
//! 22 over a stream the caller opens, with no system `ssh`. The demo opens
//! that stream from the world's jump host, so the session crosses the
//! world's network as an admin's would, and forwards VNC through it as an
//! admin tunnels it.

use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::ChannelStream;
use russh::client::{self, Handle, Handler, Msg};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use tokio::io::{AsyncRead, AsyncWrite};

/// How long one connection attempt may take, from dialing to logging in.
const ATTEMPT: Duration = Duration::from_secs(30);

/// Quotes one literal argument for the guest's POSIX shell, including
/// embedded single quotes, so data put in a command never expands.
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// An SSH identity: a cloud guest's per run, or a prepared image's admin key
/// from its build.
pub struct Identity {
    key: Arc<PrivateKey>,
    /// The public key as one `authorized_keys` line.
    pub authorized_key: String,
}

impl Identity {
    /// Generates a fresh ed25519 key from the operating system's randomness.
    pub fn generate() -> io::Result<Identity> {
        Self::new(
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .map_err(|e| io::Error::other(format!("ssh key generation: {e}")))?,
        )
    }

    /// Reads a private key that [`Identity::write`] wrote.
    pub fn read(path: &Path) -> io::Result<Identity> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        Self::new(
            PrivateKey::from_openssh(text)
                .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?,
        )
    }

    /// Writes the private key in OpenSSH format, readable only by its owner.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let text = self
            .key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| io::Error::other(format!("ssh private key: {e}")))?;
        super::image::write_private(path, &text)
    }

    fn new(key: PrivateKey) -> io::Result<Identity> {
        let authorized_key = key
            .public_key()
            .to_openssh()
            .map_err(|e| io::Error::other(format!("ssh public key: {e}")))?;
        Ok(Identity {
            key: Arc::new(key),
            authorized_key,
        })
    }
}

/// What a command printed, and how it ended.
pub struct Output {
    /// The remote exit status, or minus one if none was reported.
    pub code: i32,
    /// The command standard output.
    pub stdout: String,
    /// The command standard error.
    pub stderr: String,
}

/// Opens a new SSH session with one guest. Each viewer's terminal and
/// screen gets a session of its own: russh delivers every channel of a
/// session from one loop, so a viewer that stops reading would stall the
/// others.
pub type Dialer = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn Future<Output = io::Result<Arc<Session>>> + Send>>
        + Send
        + Sync,
>;

/// An SSH session with the guest: the commands the demo runs, and the
/// tunnels the viewer uses.
pub struct Session {
    handle: Handle<Client>,
}

impl Session {
    /// Connects over a stream from `dial`, retrying until sshd answers or
    /// `deadline` passes, then authenticates as `user` with `identity`.
    pub async fn connect<D, F, S>(
        dial: D,
        identity: &Identity,
        user: &str,
        deadline: Duration,
    ) -> io::Result<Session>
    where
        D: Fn() -> F,
        F: Future<Output = io::Result<S>>,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let start = std::time::Instant::now();
        let config = Arc::new(client::Config::default());
        loop {
            // One attempt is bounded too: a connection that sshd accepts but
            // never answers must not outlast the deadline.
            let attempt = tokio::time::timeout(ATTEMPT, async {
                Self::handshake(dial().await?, &config, identity, user).await
            })
            .await
            .unwrap_or_else(|_| Err(io::Error::other("sshd did not answer")));
            match attempt {
                Ok(session) => return Ok(session),
                Err(error) => {
                    if start.elapsed() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("sshd was not ready in {deadline:?}: {error}"),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    async fn handshake<S>(
        stream: S,
        config: &Arc<client::Config>,
        identity: &Identity,
        user: &str,
    ) -> io::Result<Session>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut handle = client::connect_stream(config.clone(), stream, Client)
            .await
            .map_err(|e| io::Error::other(format!("ssh handshake: {e}")))?;
        let authed = handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(identity.key.clone(), None))
            .await
            .map_err(|e| io::Error::other(format!("ssh auth: {e}")))?;
        if !authed.success() {
            return Err(io::Error::other("ssh public-key authentication rejected"));
        }
        Ok(Session { handle })
    }

    /// Opens a `direct-tcpip` channel to `host:port` as the guest sees it,
    /// as `ssh -L` does, for a client of ours at `originator`'s port.
    pub async fn forward(
        &self,
        host: &str,
        port: u16,
        originator: u16,
    ) -> io::Result<ChannelStream<Msg>> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(host, port.into(), "127.0.0.1", originator.into())
            .await
            .map_err(|e| io::Error::other(format!("forwarding to {host}:{port}: {e}")))?;
        Ok(channel.into_stream())
    }

    /// Opens a PTY and runs a command, or a login shell when no command is given.
    pub async fn pty(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
        command: Option<&str>,
    ) -> io::Result<Pty> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(io::Error::other)?;
        let mut channel = ClosingChannel(Some(channel));
        channel
            .request_pty(true, term, cols, rows, 0, 0, &[])
            .await
            .map_err(io::Error::other)?;
        request_accepted(&mut channel, "pty-req").await?;
        if let Some(command) = command {
            channel
                .exec(true, command)
                .await
                .map_err(io::Error::other)?;
            request_accepted(&mut channel, "exec").await?;
        } else {
            channel
                .request_shell(true)
                .await
                .map_err(io::Error::other)?;
            request_accepted(&mut channel, "shell").await?;
        }
        Ok(Pty { channel })
    }

    /// Runs `command` and returns what it printed and its exit code.
    pub async fn run(&self, command: &str) -> io::Result<Output> {
        self.run_bounded(command, usize::MAX).await
    }

    /// Runs a command with a bound on combined stdout and stderr bytes.
    /// Closes the channel and reports an error when output exceeds the bound.
    pub async fn run_bounded(&self, command: &str, max_bytes: usize) -> io::Result<Output> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| io::Error::other(format!("open session: {e}")))?;
        let mut channel = ClosingChannel(Some(channel));
        channel
            .exec(true, command)
            .await
            .map_err(|e| io::Error::other(format!("exec: {e}")))?;
        let mut output = Output {
            code: -1,
            stdout: String::new(),
            stderr: String::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        // Read until the channel is fully closed (`wait` returns `None`), so
        // the exit status is captured even when it arrives after EOF.
        while let Some(msg) = channel.wait().await {
            let added = match &msg {
                russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                    data.len()
                }
                _ => 0,
            };
            if added > max_bytes.saturating_sub(out.len() + err.len()) {
                channel.close().await.map_err(io::Error::other)?;
                return Err(io::Error::other("command output exceeded its byte limit"));
            }
            match msg {
                russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
                russh::ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => output.code = exit_status as i32,
                _ => {}
            }
        }
        output.stdout = String::from_utf8_lossy(&out).into_owned();
        output.stderr = String::from_utf8_lossy(&err).into_owned();
        Ok(output)
    }
}

/// Accepts the guest's host key: the guest is this run's own, reached only
/// through the world in this process, so there is nothing to pin.
struct Client;

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A `rand_core` source over the OS, for ssh-key's generator.
struct OsRng;

impl russh::keys::ssh_key::rand_core::TryRng for OsRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_ne_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_ne_bytes(b))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        fictionet::random_bytes(dest).expect("the system random source");
        Ok(())
    }
}

impl russh::keys::ssh_key::rand_core::TryCryptoRng for OsRng {}

/// A shell channel whose reads apply backpressure through russh's bounded channel and window.
pub struct Pty {
    channel: ClosingChannel,
}

impl Pty {
    /// Sends input to the shell.
    pub async fn write(&self, input: &[u8]) -> io::Result<()> {
        self.channel.data(input).await.map_err(io::Error::other)
    }
    /// Returns one output chunk, or None when the shell closes.
    /// Reading applies backpressure through russh's bounded channel and window.
    pub async fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        while let Some(message) = self.channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                    return Ok(Some(data.to_vec()));
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => return Ok(None),
                _ => {}
            }
        }
        Ok(None)
    }
    /// Changes the terminal size in columns and rows.
    pub async fn resize(&self, cols: u32, rows: u32) -> io::Result<()> {
        self.channel
            .window_change(cols, rows, 0, 0)
            .await
            .map_err(io::Error::other)
    }
    /// Sends EOF and closes the shell channel.
    pub async fn close(&self) -> io::Result<()> {
        self.channel.eof().await.map_err(io::Error::other)?;
        self.channel.close().await.map_err(io::Error::other)
    }
}

async fn request_accepted(channel: &mut russh::Channel<Msg>, request: &str) -> io::Result<()> {
    while !request_reply(channel.wait().await, request)? {}
    Ok(())
}

fn request_reply(message: Option<russh::ChannelMsg>, request: &str) -> io::Result<bool> {
    match message {
        Some(russh::ChannelMsg::Success) => Ok(true),
        Some(russh::ChannelMsg::Failure) => {
            Err(io::Error::other(format!("the guest refused {request}")))
        }
        // russh has already updated the write window. Keep waiting for the reply.
        Some(russh::ChannelMsg::WindowAdjusted { .. }) => Ok(false),
        Some(message) => Err(io::Error::other(format!(
            "waiting for {request} reply: unexpected {message:?}"
        ))),
        None => Err(io::Error::other(format!(
            "waiting for {request} reply: channel ended"
        ))),
    }
}

#[cfg(test)]
pub(super) mod tests;

// russh Channel has no close-on-drop; ChannelStream does.
struct ClosingChannel(Option<russh::Channel<Msg>>);

impl std::ops::Deref for ClosingChannel {
    type Target = russh::Channel<Msg>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("channel is owned until drop")
    }
}
impl std::ops::DerefMut for ClosingChannel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("channel is owned until drop")
    }
}
impl Drop for ClosingChannel {
    fn drop(&mut self) {
        if let Some(channel) = self.0.take() {
            drop(channel.into_stream());
        }
    }
}
