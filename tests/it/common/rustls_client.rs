//! A rustls client over a simulated connection.

use fictionet::Cx;
use fictionet::stdlib::network::{ConnError, Connection, ConnectionExt};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

#[derive(Debug)]
#[allow(dead_code)] // The fields show in failure messages.
pub enum ClientError {
    Conn(ConnError),
    Tls(rustls::Error),
    /// The connection ended without close_notify.
    Truncated,
}

impl From<ConnError> for ClientError {
    fn from(e: ConnError) -> Self {
        ClientError::Conn(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ClientError {}

pub struct Client<C> {
    conn: C,
    pub tls: ClientConnection,
    /// Bytes read from the connection that rustls has not taken yet: it
    /// takes no more while it holds plaintext for the reader.
    unread: Vec<u8>,
}

impl<C: Connection> Client<C> {
    pub async fn connect(
        fcx: &Cx,
        conn: C,
        config: Arc<ClientConfig>,
        name: &str,
    ) -> Result<Self, ClientError> {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let tls = ClientConnection::new(config, name).unwrap();
        let mut c = Client {
            conn,
            tls,
            unread: Vec::new(),
        };
        while c.tls.is_handshaking() {
            c.flush(fcx).await?;
            if !c.tls.is_handshaking() {
                break;
            }
            c.read_more(fcx).await?;
        }
        c.flush(fcx).await?;
        Ok(c)
    }

    pub async fn flush(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        while self.tls.wants_write() {
            let mut out = Vec::new();
            self.tls.write_tls(&mut out).unwrap();
            self.conn.write_all(fcx, &out).await?;
        }
        Ok(())
    }

    /// Reads one chunk from the connection, unless bytes read before are
    /// still waiting, and gives rustls what it takes of them, processing
    /// each record. rustls takes no more while it holds plaintext for the
    /// reader: the rest waits for the next call.
    pub async fn read_more(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        if self.unread.is_empty() {
            let mut buf = vec![0; 16 * 1024];
            let n = self.conn.read(fcx, &mut buf).await?;
            if n == 0 && self.tls.is_handshaking() {
                return Err(ClientError::Truncated);
            }
            buf.truncate(n);
            self.unread = buf;
        }
        loop {
            let mut data = &self.unread[..];
            self.tls.read_tls(&mut data).unwrap();
            let taken = self.unread.len() - data.len();
            self.unread.drain(..taken);
            let r = self.tls.process_new_packets();
            // Send any alert or reply before reporting.
            let _ = self.flush(fcx).await;
            r.map_err(ClientError::Tls)?;
            if self.unread.is_empty() || !self.tls.wants_read() {
                return Ok(());
            }
        }
    }

    /// Reads application data. `Ok(0)` is the server's close_notify.
    pub async fn read(&mut self, fcx: &Cx, buf: &mut [u8]) -> Result<usize, ClientError> {
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => self.read_more(fcx).await?,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    return Err(ClientError::Truncated);
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    pub async fn write_all(&mut self, fcx: &Cx, mut data: &[u8]) -> Result<(), ClientError> {
        while !data.is_empty() {
            let n = self
                .tls
                .writer()
                .write(&data[..data.len().min(16 * 1024)])
                .unwrap();
            data = &data[n..];
            self.flush(fcx).await?;
        }
        Ok(())
    }

    /// Sends close_notify and a FIN. Reading still works.
    pub async fn close(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        assert!(
            self.tls.send_close_notify(),
            "a client without a budget always queues its close_notify"
        );
        self.flush(fcx).await?;
        self.conn.shutdown(fcx).await?;
        Ok(())
    }
}
