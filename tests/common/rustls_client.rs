//! A rustls client over a simulated connection.

use fictionet::Cx;
use fictionet::stdlib::{ConnError, Connection, ConnectionExt, tls};
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

pub struct Client<C, const WORLD_CONTEXT: bool> {
    conn: C,
    pub tls: ClientConnection,
}

impl<C: Connection, const WORLD_CONTEXT: bool> Client<C, WORLD_CONTEXT> {
    pub async fn connect(
        fcx: &Cx,
        conn: C,
        config: Arc<ClientConfig>,
        name: &str,
    ) -> Result<Self, ClientError> {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let make = || ClientConnection::new(config, name);
        let tls = if WORLD_CONTEXT {
            tls::with_context(fcx, make)
        } else {
            make()
        }
        .unwrap();
        let mut c = Client { conn, tls };
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

    /// Reads one chunk from the connection and processes it.
    pub async fn read_more(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        let mut buf = vec![0; 16 * 1024];
        let n = self.conn.read(fcx, &mut buf).await?;
        if n == 0 && self.tls.is_handshaking() {
            return Err(ClientError::Truncated);
        }
        let mut data = &buf[..n];
        loop {
            self.tls.read_tls(&mut data).unwrap();
            let r = if WORLD_CONTEXT {
                tls::with_context(fcx, || self.tls.process_new_packets())
            } else {
                self.tls.process_new_packets()
            };
            // Send any alert or reply before reporting.
            let _ = self.flush(fcx).await;
            r.map_err(ClientError::Tls)?;
            if data.is_empty() {
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
        self.tls.send_close_notify();
        self.flush(fcx).await?;
        self.conn.shutdown(fcx).await?;
        Ok(())
    }
}
