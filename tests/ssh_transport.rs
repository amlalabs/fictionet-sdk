#![cfg(feature = "tokio")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::network::{ConnInfo, ip, tcp};
use fictionet::stdlib::protocols::ssh::{self as wire, transport::HostKey};
use fictionet::stdlib::services::ssh::{self, transport::*};
use fictionet::stdlib::world::net::{Arrival, PortServer};
use fictionet::tokio::ConnectionTokioExt;

#[derive(Default)]
struct Exchanges {
    session_id: Vec<u8>,
    initial: usize,
    rekeys: usize,
    refused: usize,
}

// A transport policy extension: refuse peers preferring the disallowed group.
// It uses only the public packet boundary; authentication and channels are stdlib.
struct RestrictedTransport {
    inner: StandardTransport,
    exchanges: Arc<Mutex<Exchanges>>,
}
impl PacketTransport for RestrictedTransport {
    fn resident_bytes(&self) -> usize {
        self.inner.resident_bytes()
    }
    fn start(&mut self, seed: [u8; 32], out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.inner.start(seed, out)
    }
    fn push(&mut self, bytes: &[u8]) -> usize {
        self.inner.push(bytes)
    }
    fn end(&mut self) {
        self.inner.end();
    }
    fn state(&self) -> State<'_> {
        self.inner.state()
    }
    fn needs_rekey(&self) -> bool {
        self.inner.needs_rekey()
    }
    fn rekey(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.inner.rekey(out)
    }
    fn write_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.inner.write_packet(payload, out)
    }
    fn disconnect(
        &mut self,
        reason: wire::DisconnectReason,
        description: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        self.inner.disconnect(reason, description, out)
    }
    fn poll_ready(&self) -> bool {
        self.inner.poll_ready()
    }
    fn poll(&mut self, out: &mut Vec<u8>) -> Result<Option<Event>, Failure> {
        let event = self.inner.poll(out)?;
        if let Some(Event::Observed(Observation::Proposal(proposal))) = &event
            && proposal
                .kex_algorithms
                .first()
                .is_some_and(|name| name == "ecdh-sha2-nistp384")
        {
            self.exchanges.lock().unwrap().refused += 1;
            return Err(TransportError::Algorithm.into());
        }
        if let Some(Event::Established { rekey }) = &event {
            let State::Established {
                session_id,
                negotiated,
            } = self.state()
            else {
                panic!("completed exchange must install keys")
            };
            assert_eq!(negotiated.kex, "curve25519-sha256");
            let mut exchanges = self.exchanges.lock().unwrap();
            if *rekey {
                assert_eq!(session_id, exchanges.session_id);
                exchanges.rekeys += 1;
            } else {
                assert!(!session_id.is_empty());
                exchanges.session_id = session_id.to_vec();
                exchanges.initial += 1;
            }
        }
        Ok(event)
    }
}

struct Echo;
impl ssh::Handler for Echo {
    type Session = Self;
    fn authenticate(
        &self,
        _: &ssh::Context<'_>,
        attempt: &ssh::AuthAttempt<'_>,
    ) -> ssh::AuthDecision {
        if matches!(
            attempt.request.method,
            wire::auth::Method::PublicKey {
                signature: Some(_),
                ..
            }
        ) {
            assert!(attempt.signature_verified);
        }
        ssh::AuthDecision::Accept
    }
    fn open(
        &self,
        _: &ssh::Context<'_>,
        _: &ssh::SessionRequest,
        _: &mut ssh::Output,
    ) -> Option<Self> {
        Some(Self)
    }
}
impl ssh::Session for Echo {
    fn input(&mut self, _: &ssh::Context<'_>, bytes: &[u8], out: &mut ssh::Output) {
        out.write(bytes).unwrap();
    }
    fn event(&mut self, _: &ssh::Context<'_>, event: &ssh::SessionEvent, out: &mut ssh::Output) {
        if matches!(event, ssh::SessionEvent::Eof) {
            out.exit(0);
        }
    }
}
struct Client;
impl russh::client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn custom_transport_keeps_standard_public_key_authentication_channels_and_rekey() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for refused in [false, true] {
            let exchanges = Arc::new(Mutex::new(Exchanges::default()));
            let observed = exchanges.clone();
            fictionet::run(fictionet::Seed::from_u64(42), move |fcx| async move {
                let (a, b) = fictionet::pair();
                let (a, _, _, _) = ip::split_protocols(&fcx, a);
                let (b, _, _, _) = ip::split_protocols(&fcx, b);
                let server = tcp::endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
                let client = tcp::endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
                let mut listener = server.listen(22)?;
                let budget = Budget::new(32 << 20);
                let server_budget = budget.clone();
                let task = fcx.spawn(move |fcx| async move {
                    let connection = listener.accept(&fcx).await?;
                    let arrival = Arrival {
                        info: ConnInfo::new(1, connection.local_addr(), connection.peer_addr()),
                        socket: Arc::new(connection.gone_watch()),
                        conn: Box::new(connection),
                        budget: Some(server_budget),
                        limits: Default::default(),
                    };
                    let server = ssh::Server {
                        config: Arc::new(ssh::Config::new(
                            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
                            wire::Identification::new("2.0", "test", None).unwrap(),
                        )),
                        handler: Arc::new(Echo),
                        limits: Default::default(),
                        budget: None,
                        backlog: None,
                    }
                    .with_transport(move |opening| {
                        assert_eq!(opening.info.local.unwrap().port(), 22);
                        assert!(opening.login_deadline > opening.now);
                        RestrictedTransport {
                            inner: StandardTransport::new(opening.config),
                            exchanges: exchanges.clone(),
                        }
                    });
                    server.serve_connection(fcx, arrival).await;
                    Ok(())
                });
                let connection = client.connect(&fcx, "10.0.0.1:22".parse().unwrap()).await?;
                let mut config = russh::client::Config::default();
                config.preferred.kex = std::borrow::Cow::Owned(vec![if refused {
                    russh::kex::ECDH_SHA2_NISTP384
                } else {
                    russh::kex::CURVE25519
                }]);
                let result = russh::client::connect_stream(
                    Arc::new(config),
                    connection.into_tokio(&fcx),
                    Client,
                )
                .await;
                if refused {
                    assert!(result.is_err());
                } else {
                    let mut client = result?;
                    let key = russh::keys::PrivateKey::from(
                        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]),
                    );
                    assert!(
                        client
                            .authenticate_publickey(
                                "guest",
                                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None)
                            )
                            .await?
                            .success()
                    );
                    let mut channel = client.channel_open_session().await?;
                    channel.exec(true, b"echo".to_vec()).await?;
                    client.rekey_soon().await?;
                    channel.data(&b"transport replacement"[..]).await?;
                    channel.eof().await?;
                    let mut received = Vec::new();
                    let mut status = None;
                    while let Some(message) = channel.wait().await {
                        match message {
                            russh::ChannelMsg::Data { data } => received.extend_from_slice(&data),
                            russh::ChannelMsg::ExitStatus { exit_status } => {
                                status = Some(exit_status)
                            }
                            russh::ChannelMsg::Close => break,
                            _ => {}
                        }
                    }
                    assert_eq!(received, b"transport replacement");
                    assert_eq!(status, Some(0));
                    client
                        .disconnect(russh::Disconnect::ByApplication, "done", "")
                        .await?;
                    drop(client);
                }
                task.join(&fcx).await?;
                assert_eq!(budget.used(), 0);
                fcx.cancel();
                Ok(())
            })
            .await
            .unwrap();
            let exchanges = observed.lock().unwrap();
            assert_eq!(exchanges.refused, usize::from(refused));
            if !refused {
                assert_eq!(exchanges.initial, 1);
                assert!(exchanges.rekeys > 0);
            }
        }
    })
    .await
    .unwrap();
}
