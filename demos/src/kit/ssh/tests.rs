use super::*;
use russh::server::{self, Auth};
use russh::{Channel, ChannelId, CryptoVec};
use tokio::sync::mpsc;

use std::collections::HashSet;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    events: mpsc::UnboundedSender<String>,
    ready: Arc<AtomicBool>,
    rfb: Arc<Mutex<Vec<u8>>>,
    forwards: HashSet<ChannelId>,
    tasks: tokio::task::JoinSet<io::Result<()>>,
}

/// An authenticated SSH peer with a PTY, controllable readiness, and an RFB desktop.
/// Page tests can reuse this peer without a VM or host listener.
pub(crate) struct Peer {
    pub session: Arc<Session>,
    pub events: mpsc::UnboundedReceiver<String>,
    pub ready: Arc<AtomicBool>,
    pub rfb: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    pub async fn new() -> Self {
        let identity = Identity::generate().unwrap();
        let (client, stream) = tokio::io::duplex(64 << 10);
        let (events, rx) = mpsc::unbounded_channel();
        let ready = Arc::new(AtomicBool::new(false));
        let rfb = Arc::new(Mutex::new(Vec::new()));
        let handler = Server {
            events,
            ready: ready.clone(),
            rfb: rfb.clone(),
            forwards: HashSet::new(),
            tasks: tokio::task::JoinSet::new(),
        };
        let config = server::Config {
            keys: vec![(*identity.key).clone()],
            ..Default::default()
        };
        let task = tokio::spawn(async move {
            server::run_stream(Arc::new(config), stream, handler)
                .await
                .unwrap()
                .await
                .unwrap();
        });
        let session = Session::handshake(
            client,
            &Arc::new(client::Config::default()),
            &identity,
            "analyst",
        )
        .await
        .unwrap();
        Self {
            session: Arc::new(session),
            events: rx,
            ready,
            rfb,
            task,
        }
    }
}

impl server::Handler for Server {
    type Error = russh::Error;
    async fn auth_publickey(&mut self, _: &str, _: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.events
            .send(format!("pty {term} {cols} {rows}"))
            .unwrap();
        session.channel_success(id)?;
        Ok(())
    }
    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.events.send("shell".into()).unwrap();
        session.channel_success(id)?;
        session.data(id, CryptoVec::from_slice(b"ready"))?;
        Ok(())
    }
    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if !self.forwards.contains(&id) {
            if data == b"large-output\r" {
                let output: Vec<u8> = (0..512 * 1024).map(|n| (n % 251) as u8).collect();
                session.data(id, CryptoVec::from_slice(&output))?;
            } else {
                session.data(id, CryptoVec::from_slice(data))?;
            }
        }
        Ok(())
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        assert_eq!((host, port), ("127.0.0.1", 5901));
        self.forwards.insert(channel.id());
        let messages = self.rfb.clone();
        self.tasks.spawn(fake_rfb(channel.into_stream(), messages));
        Ok(true)
    }
    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let command = std::str::from_utf8(command).unwrap();
        let ready = self.ready.load(Ordering::SeqCst);
        session.channel_success(id)?;
        if !ready {
            session.extended_data(
                id,
                1,
                CryptoVec::from_slice(b"window manager is not running"),
            )?;
        }
        session.exit_status_request(id, if ready { 0 } else { 7 })?;
        session.eof(id)?;
        session.close(id)?;
        self.events.send(format!("exec {command}")).unwrap();
        Ok(())
    }
    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.events.send(format!("size {cols} {rows}")).unwrap();
        Ok(())
    }
    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.events.send("closed".into()).unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn shell_input_output_resize_and_close() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let identity = Identity::generate().unwrap();
        let (client, server_stream) = tokio::io::duplex(4096);
        let (tx, mut events) = mpsc::unbounded_channel();
        let config = server::Config {
            keys: vec![(*identity.key).clone()],
            ..Default::default()
        };
        let server = tokio::spawn(async move {
            server::run_stream(
                Arc::new(config),
                server_stream,
                Server {
                    events: tx,
                    ready: Arc::new(AtomicBool::new(false)),
                    rfb: Arc::new(Mutex::new(Vec::new())),
                    forwards: HashSet::new(),
                    tasks: tokio::task::JoinSet::new(),
                },
            )
            .await
            .unwrap()
            .await
            .unwrap();
        });
        let session = Session::handshake(
            client,
            &Arc::new(client::Config::default()),
            &identity,
            "analyst",
        )
        .await
        .unwrap();
        let mut pty = session.pty("xterm-256color", 80, 24).await.unwrap();
        assert_eq!(events.recv().await.unwrap(), "pty xterm-256color 80 24");
        assert_eq!(events.recv().await.unwrap(), "shell");
        assert_eq!(pty.read().await.unwrap().unwrap(), b"ready");
        pty.write(b"hello\r").await.unwrap();
        assert_eq!(pty.read().await.unwrap().unwrap(), b"hello\r");
        pty.resize(120, 40).await.unwrap();
        assert_eq!(events.recv().await.unwrap(), "size 120 40");
        pty.close().await.unwrap();
        assert_eq!(events.recv().await.unwrap(), "closed");
        // Another shell uses the same authenticated connection.
        let mut second = session.pty("vt100", 40, 20).await.unwrap();
        assert_eq!(second.read().await.unwrap().unwrap(), b"ready");
        second.close().await.unwrap();
        server.abort();
        let _ = server.await;
    })
    .await
    .unwrap();
}

async fn fake_rfb(
    mut stream: russh::ChannelStream<server::Msg>,
    messages: Arc<Mutex<Vec<u8>>>,
) -> io::Result<()> {
    stream.write_all(b"RFB 003.008\n").await?;
    let mut banner = [0; 12];
    stream.read_exact(&mut banner).await?;
    assert_eq!(&banner, b"RFB 003.008\n");
    stream.write_all(&[1, 1]).await?;
    assert_eq!(stream.read_u8().await?, 1);
    stream.write_all(&[0; 4]).await?;
    assert_eq!(stream.read_u8().await?, 1);
    let mut init = vec![
        0, 64, 0, 64, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
    ];
    init.extend_from_slice(&4u32.to_be_bytes());
    init.extend_from_slice(b"Desk");
    stream.write_all(&init).await?;
    loop {
        let kind = match stream.read_u8().await {
            Ok(kind) => kind,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        messages.lock().unwrap().push(kind);
        match kind {
            0 => {
                let mut format = [0; 19];
                stream.read_exact(&mut format).await?;
            }
            2 => {
                stream.read_u8().await?;
                let n = stream.read_u16().await?;
                for _ in 0..n {
                    stream.read_i32().await?;
                }
            }
            3 => {
                let mut request = [0; 9];
                stream.read_exact(&mut request).await?;
                let mut frame = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 64, 0, 64, 0, 0, 0, 0];
                for y in 0..64u8 {
                    for x in 0..64u8 {
                        frame.extend_from_slice(&[x * 4, y * 4, x ^ y, 0]);
                    }
                }
                stream.write_all(&frame).await?;
            }
            other => panic!("unexpected RFB input {other}"),
        }
    }
}

#[tokio::test]
async fn dropping_a_pty_closes_its_channel() {
    let mut peer = Peer::new().await;
    let pty = peer.session.pty("xterm", 80, 24).await.unwrap();
    drop(pty);
    tokio::time::timeout(Duration::from_secs(5), async {
        while peer.events.recv().await.as_deref() != Some("closed") {}
    })
    .await
    .unwrap();
}
