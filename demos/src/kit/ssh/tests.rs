use super::*;
use russh::server::{self, Auth};
use russh::{Channel, ChannelId, CryptoVec};
use tokio::sync::mpsc;

struct Server(mpsc::UnboundedSender<String>);
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
        self.0.send(format!("pty {term} {cols} {rows}")).unwrap();
        session.channel_success(id)?;
        Ok(())
    }
    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.0.send("shell".into()).unwrap();
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
        session.data(id, CryptoVec::from_slice(data))?;
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
        self.0.send(format!("size {cols} {rows}")).unwrap();
        Ok(())
    }
    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.0.send("closed".into()).unwrap();
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
            server::run_stream(Arc::new(config), server_stream, Server(tx))
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
