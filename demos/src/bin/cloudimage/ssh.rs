//! An embedded SSH client that reaches the guest's sshd over Cloud
//! Hypervisor's hybrid vsock, with no system `ssh` and nothing listening on
//! a network port.
//!
//! CH exposes the guest's vsock as a host Unix socket. A client connects to
//! it, sends `CONNECT <port>\n`, reads back `OK <n>\n`, and from then on the
//! stream is wired to that guest vsock port. We run russh over that stream.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle, Handler};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// A per-run SSH identity.
pub struct Identity {
    key: Arc<PrivateKey>,
    /// The public key as one `authorized_keys` line.
    pub authorized_key: String,
}

impl Identity {
    /// Generates a fresh ed25519 key from the operating system's randomness.
    pub fn generate() -> io::Result<Identity> {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| io::Error::other(format!("ssh key generation: {e}")))?;
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
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// A connection to the guest over vsock. The control-plane client: a
/// hypervisor integration opens it to run commands once the VMM is chosen.
pub struct Session {
    handle: Handle<Client>,
}

impl Session {
    /// Connects over the CH vsock socket to the guest's port 22, retrying
    /// until sshd answers or `deadline` passes, then authenticates as
    /// `user` with `identity`.
    pub async fn connect(
        vsock_socket: &Path,
        identity: &Identity,
        user: &str,
        deadline: Duration,
    ) -> io::Result<Session> {
        let start = std::time::Instant::now();
        let config = Arc::new(client::Config::default());
        loop {
            match Self::try_connect(vsock_socket, &config, identity, user).await {
                Ok(session) => return Ok(session),
                Err(error) => {
                    if start.elapsed() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("sshd over vsock was not ready in {deadline:?}: {error}"),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    async fn try_connect(
        vsock_socket: &Path,
        config: &Arc<client::Config>,
        identity: &Identity,
        user: &str,
    ) -> io::Result<Session> {
        let mut stream = UnixStream::connect(vsock_socket).await?;
        // CH's hybrid vsock handshake: ask for guest port 22.
        stream.write_all(b"CONNECT 22\n").await?;
        let mut line = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            line.push(byte);
            if line.len() > 64 {
                return Err(io::Error::other("vsock handshake reply too long"));
            }
        }
        if !line.starts_with(b"OK") {
            return Err(io::Error::other(format!(
                "vsock refused the connection: {}",
                String::from_utf8_lossy(&line)
            )));
        }
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

    /// Runs `command` and returns what it printed and its exit code.
    pub async fn run(&self, command: &str) -> io::Result<Output> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| io::Error::other(format!("open session: {e}")))?;
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
/// over its private vsock, so there is nothing to pin.
struct Client;

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A `rand_core` 0.6 source over the OS, for ssh-key's generator.
struct OsRng;

impl russh::keys::ssh_key::rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_ne_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_ne_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(dest))
            .expect("read /dev/urandom");
    }
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), russh::keys::ssh_key::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl russh::keys::ssh_key::rand_core::CryptoRng for OsRng {}
