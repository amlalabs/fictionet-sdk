//! The guest agent: microsandbox's `agentd`, driven over the console port
//! named `agent` with microsandbox's own protocol and client.
//!
//! agentd starts as the guest's first process and reads one bootstrap
//! frame. It mounts the block device as the root and pivots into it,
//! installs the CA the parent left in the runtime share, and reports the
//! user commands will run as; the parent acknowledges. Then it sends
//! `core.ready`. In microsandbox a relay sits between agentd and its
//! clients; here the parent plays the relay's part for one client, so the
//! client sees what a relay would have sent it.
//!
//! The bootstrap leaves the network to the guest: agentd brings up only
//! the loopback, and the guest's own DHCP client configures the card from
//! the world's answers.

use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use microsandbox_agent_client::{AgentClient, TypedMessage};
use microsandbox_protocol::bootstrap::{BootstrapBlockRoot, BootstrapEnvVar, GuestBootstrap};
use microsandbox_protocol::codec;
use microsandbox_protocol::core::{CoreError, InitAck};
use microsandbox_protocol::exec::{
    ExecExited, ExecFailed, ExecRequest, ExecStderr, ExecStdin, ExecStdout,
};
use microsandbox_protocol::message::{FLAG_TERMINAL, Message, MessageType};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UnixStream;

/// The search path commands run with, the one the usual images set.
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Writes agentd's bootstrap to the parent's end of the console, where it
/// waits until agentd reads it.
pub(crate) fn send_bootstrap(console: &OwnedFd) -> io::Result<()> {
    use std::io::Write;
    let bootstrap = GuestBootstrap {
        block_root: Some(BootstrapBlockRoot::DiskImage {
            device: "/dev/vda".into(),
            fstype: Some("ext4".into()),
        }),
        hostname: Some("agent".into()),
        default_env: vec![BootstrapEnvVar {
            key: "PATH".into(),
            value: PATH.into(),
        }],
        ..GuestBootstrap::default()
    };
    let message =
        Message::with_payload(MessageType::Bootstrap, 0, &bootstrap).map_err(io::Error::other)?;
    let mut frame = Vec::new();
    codec::encode_to_buf(&message, &mut frame).map_err(io::Error::other)?;
    std::os::unix::net::UnixStream::from(console.try_clone()?).write_all(&frame)
}

/// Waits for agentd's `core.ready`, answering its init report on the way,
/// then hands the console to a client.
pub(crate) async fn connect(console: OwnedFd) -> io::Result<Agent> {
    let console = std::os::unix::net::UnixStream::from(console);
    console.set_nonblocking(true)?;
    let mut console = UnixStream::from_std(console)?;
    let ready = loop {
        let frame = codec::read_raw_frame(&mut console)
            .await
            .map_err(io::Error::other)?;
        let message = codec::raw_frame_to_message(frame.clone()).map_err(io::Error::other)?;
        match message.t {
            MessageType::Ready => break frame,
            MessageType::InitResolved => ack(&mut console, false).await?,
            MessageType::CoreError if message.id == 0 && message.flags & FLAG_TERMINAL != 0 => {
                let error: CoreError = message.payload().map_err(io::Error::other)?;
                ack(&mut console, true).await?;
                return Err(io::Error::other(format!(
                    "the guest agent failed to start: {}",
                    error.message
                )));
            }
            // agentd's boot progress, which only microsandbox's runtime reads.
            _ => {}
        }
    };
    // A relay starts each client with the range of correlation IDs it may
    // use, then agentd's ready frame.
    let mut head = Vec::new();
    head.extend_from_slice(&0u32.to_be_bytes());
    head.extend_from_slice(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes());
    codec::encode_raw_to_buf(&ready, &mut head).map_err(io::Error::other)?;
    let client = AgentClient::connect_stream(Prefixed {
        head,
        at: 0,
        inner: console,
    })
    .await
    .map_err(io::Error::other)?;
    Ok(Agent { client })
}

/// Acknowledges agentd's init report, or with `failure`, its startup
/// error.
async fn ack(console: &mut UnixStream, failure: bool) -> io::Result<()> {
    let message = Message::with_payload(MessageType::InitAck, 0, &InitAck { failure })
        .map_err(io::Error::other)?;
    let mut frame = Vec::new();
    codec::encode_to_buf(&message, &mut frame).map_err(io::Error::other)?;
    console.write_all(&frame).await
}

/// A connection to the guest agent.
pub struct Agent {
    client: AgentClient,
}

/// What a command printed, and how it ended.
#[derive(Debug, Default)]
pub struct Output {
    /// The exit code.
    pub code: i32,
    /// Everything it wrote to standard output.
    pub stdout: Vec<u8>,
    /// Everything it wrote to standard error.
    pub stderr: Vec<u8>,
}

impl Agent {
    /// How long the guest kernel took to start agentd, and how long agentd
    /// then took to mount the root and set up the guest, as agentd measured
    /// them.
    pub fn boot_times(&self) -> (Duration, Duration) {
        let ready = &self.client.ready().agent;
        (
            Duration::from_nanos(ready.boot_time_ns),
            Duration::from_nanos(ready.init_time_ns),
        )
    }

    /// Runs `cmd` with `args` in the guest as root, with standard input
    /// closed, and waits for it to exit.
    pub async fn exec(&self, cmd: &str, args: &[&str]) -> io::Result<Output> {
        let request = ExecRequest {
            cmd: cmd.into(),
            args: args.iter().map(|&a| a.into()).collect(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let stream = self
            .client
            .stream(TypedMessage::new(
                MessageType::ExecRequest.as_str(),
                &request,
            ))
            .await
            .map_err(io::Error::other)?;
        let (sender, mut receiver) = stream.into_parts();
        // Empty input closes the command's standard input.
        sender
            .send(TypedMessage::new(
                MessageType::ExecStdin.as_str(),
                ExecStdin { data: Vec::new() },
            ))
            .await
            .map_err(io::Error::other)?;
        let mut output = Output::default();
        let mut exited = false;
        while let Some(message) = receiver.recv().await.map_err(io::Error::other)? {
            match MessageType::from_wire_str(&message.t) {
                Some(MessageType::ExecStdout) => output.stdout.extend(
                    message
                        .payload::<ExecStdout>()
                        .map_err(io::Error::other)?
                        .data,
                ),
                Some(MessageType::ExecStderr) => output.stderr.extend(
                    message
                        .payload::<ExecStderr>()
                        .map_err(io::Error::other)?
                        .data,
                ),
                Some(MessageType::ExecExited) => {
                    output.code = message
                        .payload::<ExecExited>()
                        .map_err(io::Error::other)?
                        .code;
                    exited = true;
                }
                Some(MessageType::ExecFailed) => {
                    let failed: ExecFailed = message.payload().map_err(io::Error::other)?;
                    return Err(io::Error::other(format!(
                        "{cmd} did not start: {}",
                        failed.message
                    )));
                }
                _ => {}
            }
        }
        if !exited {
            return Err(io::Error::other(format!("{cmd} ended with no exit status")));
        }
        Ok(output)
    }

    /// Asks agentd to stop every command and power the guest off.
    pub(crate) async fn shutdown(self) {
        // The payload is an empty CBOR map: shutdown takes no arguments.
        let message = Message::new(MessageType::Shutdown, 0, vec![0xa0]);
        let mut frame = Vec::new();
        if codec::encode_to_buf(&message, &mut frame).is_ok() {
            // The guest goes away either way: the caller kills the child
            // when it does not.
            let _ = self.client.write_unchecked(frame).await;
        }
    }
}

/// The console as a client sees it: the relay's prologue, then agentd.
struct Prefixed {
    head: Vec<u8>,
    at: usize,
    inner: UnixStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.at < self.head.len() {
            let n = buf.remaining().min(self.head.len() - self.at);
            let at = self.at;
            buf.put_slice(&self.head[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
