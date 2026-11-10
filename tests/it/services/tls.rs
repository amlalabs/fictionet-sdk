use super::*;
use fictionet_test_support::sandbox::TlsClient;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::task::Waker;

use fictionet::stdlib::layer::{
    Admit, ByteStream, Chain, Chunk, Env, Handoff, Handover, Harness, Layer, Side, StreamCommand,
    StreamEvent, Switch, Top,
};
use fictionet::stdlib::services::stack::{self, Job, Polling, StreamLimits};
use fictionet::stdlib::services::tls::{Secure, TlsLayer};
use fictionet::time::Instant;

// ---------------------------------------------------------------------------
// TLS by name

/// A server config for `names`, and roots that trust it.
fn tls_pair(fcx: &Cx, names: &[&str]) -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
    let (ca, leaf) = certs::issue(fcx, "Test CA", names).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    (
        leaf.server_config(fcx, std::time::SystemTime::now())
            .unwrap(),
        Arc::new(roots),
    )
}

/// A connection whose TLS handshake is cut short by a cancel ends as
/// cancelled, not as a broken connection.
#[test]
fn a_cancel_during_the_tls_handshake_is_a_cancel() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let (config, _roots) = tls_pair(&fcx, &["a.test"]);
        let (server, _su, client, _cu) = two_machines(&fcx);
        let mut listener = server.listen(443)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            let _ = fcx
                .region(|region_fcx| async move {
                    let stopper = region_fcx.clone();
                    region_fcx.spawn(move |fcx| async move {
                        fcx.sleep(Duration::from_millis(50)).await?;
                        stopper.cancel();
                        Ok(())
                    });
                    let tls = Chain::new(TlsLayer::new(config), Mail::secure(ConnInfo::default()));
                    let served = stack::stream(
                        &region_fcx,
                        conn,
                        &ConnInfo::default(),
                        tls,
                        Budget::unlimited(),
                        StreamLimits::default(),
                        |_| {},
                    )
                    .await;
                    let _ = tx.send(format!("{:?}", served.map(|_| ())));
                    Ok(())
                })
                .await;
            Ok(())
        });
        // The client connects and never says hello.
        let _conn = client
            .connect(&fcx, SocketAddr::new(SERVER.into(), 443))
            .await?;
        let result = fcx
            .race(Some(fcx.now() + Duration::from_secs(10)), rx)
            .await??;
        // Not a closed connection, nor a broken one: the one cancel.
        assert_eq!(result, "Err(Cancelled)");
        Ok(())
    });
}

#[test]
fn net_routes_tls_by_name_to_each_service() {
    /// Answers each line in upper case.
    struct Upper;
    impl LineApp for Upper {
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Next = Infallible;
        type Error = Infallible;
        fn line(
            &mut self,
            line: Result<Vec<u8>, LineError>,
            out: &mut LineOut<'_, Self>,
        ) -> Result<(), Infallible> {
            out.write(&line.unwrap_or_default().to_ascii_uppercase());
            out.write(b"\n");
            Ok(())
        }
    }
    let result = block_on(fictionet::lab(
        fictionet::Seed::from_u64(1),
        move |fcx| async move {
            let (ca, leaf) = certs::issue(&fcx, "Test CA", &["a.test", "b.test"])?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.cert_der())?;
            let roots = Arc::new(roots);
            let config = leaf.certified_key();
            let (attacher, attachments) = fictionet::attachments();
            let (ca, cb) = (config.clone(), config.clone());
            let addr = Ipv4Addr::new(10, 40, 0, 2);
            Net::new(fictionet_extras::network::cdn_pools())
                .ipv4_only()
                .add_host(
                    fictionet::stdlib::world::net::Host::new("tls")
                        .at(addr)
                        .tls_stack(6514, "a.test", move |_| ca.clone(), |_| Echo::stack())
                        .tls_stack(6514, "b.test", move |_| cb.clone(), |_| Lined::new(Upper)),
                )
                .start(&fcx, attachments)?;
            let s = machine(&fcx, attacher.attach("agent")?, ME);
            let to = SocketAddr::new(addr.into(), 6514);
            let start = std::time::SystemTime::now();
            let mut a = s.tls(&fcx, to, "a.test", Some(&roots), start).await?;
            let mut buf = [0u8; 64];
            let n = a.read(&fcx, &mut buf).await?;
            assert_eq!(&buf[..n], b"hello\n");
            let mut b = s.tls(&fcx, to, "b.test", Some(&roots), start).await?;
            b.write_all(&fcx, b"shout\n").await?;
            let n = b.read(&fcx, &mut buf).await?;
            assert_eq!(&buf[..n], b"SHOUT\n");
            assert!(
                s.tls(&fcx, to, "c.test", Some(&roots), start)
                    .await
                    .is_err()
            );
            Err::<(), fictionet::Error>(Done.into())
        },
    ));
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

// ---------------------------------------------------------------------------
// STARTTLS

/// What a plaintext [`Mail`] session negotiates at STARTTLS: TLS, and the
/// same session over it once the handshake is done.
type MakeMail = Box<dyn FnOnce(&TlsLayer) -> Option<Mail> + Send>;
type Secured = Secure<Mail, MakeMail>;

/// A mail connection: plaintext until STARTTLS, then TLS.
type Starttls = Switch<Mail, Secured>;

/// SMTP-style STARTTLS as layers: the banner, then `STARTTLS`, then TLS on
/// the same connection with the same session above it.
///
/// After its go-ahead the session reads nothing more in plaintext: what a
/// client pipelines after STARTTLS is dropped, never read as a command and
/// never handed to TLS. TLS takes over once the go-ahead
/// is written, so no completion of a plaintext write reaches it. `SUB`
/// subscribes the session to fills, which its work waits for, on either
/// side of STARTTLS.
struct Mail {
    /// Who the session is with, and over TLS the name the client asked
    /// for.
    conn: ConnInfo,
    /// The config STARTTLS shakes hands with, and how long the client has
    /// to; `None` over TLS, where STARTTLS is refused.
    starttls: Option<(Arc<rustls::ServerConfig>, Duration)>,
    input: Vec<u8>,
    out: VecDeque<Vec<u8>>,
    produced: u64,
    written: u64,
    /// The TLS session STARTTLS negotiated, until it takes over.
    next: Option<Box<Secured>>,
    /// What came from below after STARTTLS for TLS to hear: the end of
    /// input or a reset.
    below: Vec<StreamEvent>,
    input_over: bool,
    end_sent: bool,
    /// Where `SUB` subscribes the session to fills.
    book: Book,
    /// The session's fills once it subscribed, carried across STARTTLS.
    inbox: Option<Inbox>,
    /// Whether work waits on the inbox.
    waiting: bool,
    /// What a careless session does with plaintext pipelined after
    /// STARTTLS, instead of dropping it.
    careless: Option<Careless>,
}

/// How a careless STARTTLS session leaves what the client pipelined after
/// STARTTLS to the switch.
#[derive(Clone, Copy)]
enum Careless {
    /// It hands it over, as a protocol does whose successor is a tunnel.
    HandsOver,
    /// It stops taking input at STARTTLS, and the rest waits below.
    Refuses,
}

/// Fills waiting for one subscribed session, and the waker of the work
/// that waits for them.
#[derive(Default)]
struct Fills {
    queue: VecDeque<String>,
    waker: Option<Waker>,
}

type Inbox = Arc<Mutex<Fills>>;

/// Every subscribed session's inbox.
type Book = Arc<Mutex<Vec<Inbox>>>;

/// Sends `fill` to every subscribed session and wakes its work.
fn fill(book: &Book, fill: &str) {
    for inbox in book.lock().unwrap().iter() {
        let mut fills = inbox.lock().unwrap();
        fills.queue.push_back(fill.to_owned());
        if let Some(waker) = fills.waker.take() {
            waker.wake();
        }
    }
}

/// Waits for the next fill in one inbox.
struct NextFill(Inbox);

impl Job for NextFill {
    type Done = String;

    fn poll(&mut self, _: Option<&Cx>, cx: &mut Context<'_>) -> Poll<String> {
        let mut fills = self.0.lock().unwrap();
        match fills.queue.pop_front() {
            Some(fill) => Poll::Ready(fill),
            None => {
                fills.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Mail {
    /// A plaintext session with `conn`, which offers STARTTLS with
    /// `config` and gives the client `handshake` to shake hands.
    fn plain(conn: ConnInfo, config: Arc<rustls::ServerConfig>, handshake: Duration) -> Mail {
        let mut mail = Mail::secure(conn);
        mail.starttls = Some((config, handshake));
        mail.out.push_back(b"220 mail ready\r\n".to_vec());
        mail
    }

    /// A session with `conn` over TLS, where the client speaks first.
    fn secure(conn: ConnInfo) -> Mail {
        Mail {
            conn,
            starttls: None,
            input: Vec::new(),
            out: VecDeque::new(),
            produced: 0,
            written: 0,
            next: None,
            below: Vec::new(),
            input_over: false,
            end_sent: false,
            book: Book::default(),
            inbox: None,
            waiting: false,
            careless: None,
        }
    }

    /// The same session, subscribing to fills in `book`.
    fn subscribing(mut self, book: Book) -> Mail {
        self.book = book;
        self
    }

    fn answer(&mut self, now: Instant, line: &[u8]) {
        match (line, self.starttls.take()) {
            (b"STARTTLS", Some((config, handshake))) => {
                self.out.push_back(b"220 go ahead\r\n".to_vec());
                let tls = TlsLayer::new(config).handshake_by(now + handshake);
                let conn = self.conn.clone();
                let book = self.book.clone();
                let inbox = self.inbox.clone();
                let over: MakeMail = Box::new(move |tls| {
                    let sni = tls.hello().and_then(|hello| hello.server_name());
                    let mut mail = Mail::secure(conn.over_tls(sni, tls.alpn())).subscribing(book);
                    mail.inbox = inbox;
                    Some(mail)
                });
                self.next = Some(Box::new(Secure::new(tls, over)));
            }
            (b"SUB", starttls) => {
                self.starttls = starttls;
                let inbox = Inbox::default();
                self.book.lock().unwrap().push(inbox.clone());
                self.inbox = Some(inbox);
                self.out.push_back(b"250 subscribed\r\n".to_vec());
            }
            (b"EHLO", starttls) => {
                self.starttls = starttls;
                let sni = self.conn.sni.as_deref().unwrap_or("-");
                let reply = format!("250 hello tls={} sni={sni}\r\n", self.conn.tls);
                self.out.push_back(reply.into_bytes());
            }
            (_, starttls) => {
                self.starttls = starttls;
                self.out.push_back(b"500 what\r\n".to_vec());
            }
        }
    }
}

impl Layer for Mail {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = NextFill;
    type Done = String;
    type Error = Infallible;

    fn is_terminal(&self) -> bool {
        self.end_sent
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        match event {
            StreamEvent::Written(n) => self.written += n,
            StreamEvent::Data(chunk) if self.next.is_some() => match self.careless {
                None => {}
                Some(Careless::HandsOver) => self.below.push(StreamEvent::Data(chunk)),
                Some(Careless::Refuses) => return Ok(Admit::Blocked(StreamEvent::Data(chunk))),
            },
            StreamEvent::Data(_) if self.input_over => return Ok(Admit::Closed(event)),
            StreamEvent::Data(mut chunk) => {
                self.input.extend_from_slice(&chunk);
                while self.next.is_none()
                    && let Some(end) = self.input.iter().position(|b| *b == b'\n')
                {
                    let line: Vec<u8> = self.input.drain(..=end).collect();
                    let line = line.strip_suffix(b"\n").unwrap_or(&line);
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    self.answer(env.now(), line);
                }
                if self.next.is_some() {
                    // What came after STARTTLS in this chunk.
                    let rest = std::mem::take(&mut self.input);
                    match self.careless {
                        None => {}
                        Some(Careless::HandsOver) => {
                            self.below.push(StreamEvent::Data(Chunk::unpaid(rest)))
                        }
                        Some(Careless::Refuses) if !rest.is_empty() => {
                            chunk.advance(chunk.len() - rest.len());
                            return Ok(Admit::Partial(StreamEvent::Data(chunk)));
                        }
                        Some(Careless::Refuses) => {}
                    }
                } else if self.input.len() > 512 {
                    self.input_over = true;
                }
            }
            StreamEvent::Ended | StreamEvent::Reset if self.next.is_some() => {
                self.below.push(event)
            }
            StreamEvent::Ended | StreamEvent::Reset => self.input_over = true,
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        if let Some(bytes) = self.out.pop_front() {
            self.produced += bytes.len() as u64;
            return Some(StreamCommand::Write(Chunk::unpaid(bytes)));
        }
        if self.input_over && self.next.is_none() && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<NextFill> {
        if self.waiting || self.next.is_some() {
            return None;
        }
        let inbox = self.inbox.clone()?;
        self.waiting = true;
        Some(NextFill(inbox))
    }

    fn on_done(&mut self, _env: &mut Env<'_, Infallible>, fill: String) -> Result<(), Infallible> {
        self.waiting = false;
        self.out
            .push_back(format!("250 fill {fill}\r\n").into_bytes());
        Ok(())
    }
}

impl Handoff for Mail {
    type Next = Secured;

    fn handover(&mut self) -> Option<Handover<Secured, ByteStream, Top>> {
        if !self.out.is_empty() || self.written < self.produced {
            return None;
        }
        Some(Handover {
            next: *self.next.take()?,
            below: std::mem::take(&mut self.below),
            above: Vec::new(),
        })
    }
}

/// A server config for `mail.test`, and a client config that trusts it.
fn mail_configs(fcx: &Cx) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let (config, roots) = tls_pair(fcx, &["mail.test"]);
    let start = std::time::SystemTime::now();
    let client = fictionet_test_support::sandbox::client_config(fcx, start, Some(&roots), &[]);
    (config, client.unwrap())
}

fn mail_client(config: Arc<rustls::ClientConfig>) -> rustls::ClientConnection {
    let name = rustls::pki_types::ServerName::try_from("mail.test").unwrap();
    rustls::ClientConnection::new(config, name).unwrap()
}

/// The client's ciphertext waiting to go out.
fn ciphertext(client: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    bytes
}

/// Gives the client the server's ciphertext and returns the plaintext it
/// decrypts.
fn decrypt(client: &mut rustls::ClientConnection, mut bytes: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    while !bytes.is_empty() {
        assert!(client.read_tls(&mut bytes).unwrap() > 0);
        client.process_new_packets().unwrap();
        if let Err(e) = client.reader().read_to_end(&mut plaintext) {
            assert_eq!(e.kind(), ErrorKind::WouldBlock);
        }
    }
    plaintext
}

/// The plaintext session of connection 1, offering STARTTLS and
/// subscribing to fills in `book`.
fn starttls(config: Arc<rustls::ServerConfig>, book: Book) -> Harness<Starttls> {
    let conn = ConnInfo {
        id: Some(1),
        ..ConnInfo::default()
    };
    let mail = Mail::plain(conn, config, Duration::from_secs(10)).subscribing(book);
    Harness::new(fictionet::Seed::from_u64(0), Switch::new(mail)).with_worker(Polling::new())
}

/// Fills sent to a session that subscribed before STARTTLS still reach it
/// after: the subscription goes across with the session, and wakes the
/// session over TLS.
#[test]
fn a_subscription_made_before_starttls_wakes_the_session_after_it() {
    block_on(lab(fictionet::Seed::from_u64(4), |fcx| async move {
        let (config, client_config) = mail_configs(&fcx);
        let book = Book::default();
        let mut h = starttls(config, book.clone());
        h.settle()?;
        h.take_output();
        h.push(b"SUB\r\n")?;
        assert_eq!(h.take_output(), b"250 subscribed\r\n");
        fill(&book, "7@100");
        h.settle()?;
        assert_eq!(h.take_output(), b"250 fill 7@100\r\n");
        h.push(b"STARTTLS\r\n")?;
        assert_eq!(h.take_output(), b"220 go ahead\r\n");
        let mut client = mail_client(client_config);
        for _ in 0..16 {
            h.push(&ciphertext(&mut client))?;
            decrypt(&mut client, &h.take_output());
        }
        assert!(!client.is_handshaking());
        // The client sends nothing: the fill alone wakes the session.
        fill(&book, "5@99");
        h.settle()?;
        assert_eq!(decrypt(&mut client, &h.take_output()), b"250 fill 5@99\r\n");
        Ok(())
    }))
    .unwrap();
}

#[test]
fn starttls_hands_the_session_to_tls_once_its_go_ahead_is_written() {
    block_on(lab(fictionet::Seed::from_u64(1), |fcx| async move {
        let (config, client_config) = mail_configs(&fcx);
        let mut h = starttls(config, Book::default());
        h.settle()?;
        assert_eq!(h.take_output(), b"220 mail ready\r\n");
        // While the go-ahead is not written, plaintext stays in charge.
        h.withhold();
        h.push(b"STARTTLS\r\n")?;
        assert!(h.layer().first().is_some());
        h.allow_all()?;
        assert_eq!(h.take_output(), b"220 go ahead\r\n");
        assert!(h.layer().then().is_some());
        let mut client = mail_client(client_config);
        for _ in 0..16 {
            h.push(&ciphertext(&mut client))?;
            decrypt(&mut client, &h.take_output());
        }
        assert!(!client.is_handshaking());
        client.writer().write_all(b"EHLO\r\n")?;
        h.push(&ciphertext(&mut client))?;
        assert_eq!(
            decrypt(&mut client, &h.take_output()),
            b"250 hello tls=true sni=mail.test\r\n"
        );
        // The session over TLS is the one from before STARTTLS, carried
        // across it with what TLS settled.
        let session = h.layer().then().and_then(Secure::upper).unwrap();
        assert_eq!(session.conn.id, Some(1));
        // STARTTLS again is refused, and the session goes on.
        client.writer().write_all(b"STARTTLS\r\nEHLO\r\n")?;
        h.push(&ciphertext(&mut client))?;
        assert_eq!(
            decrypt(&mut client, &h.take_output()),
            b"500 what\r\n250 hello tls=true sni=mail.test\r\n"
        );
        Ok(())
    }))
    .unwrap();
}

/// What a client pipelines after STARTTLS, before the go-ahead could reach
/// it, is not a command, and does not reach the session over TLS.
#[test]
fn plaintext_pipelined_after_starttls_is_never_read() {
    block_on(lab(fictionet::Seed::from_u64(2), |fcx| async move {
        let (config, client_config) = mail_configs(&fcx);
        let mut h = starttls(config, Book::default());
        h.settle()?;
        h.take_output();
        h.withhold();
        // In the same segment as STARTTLS, and after it while the go-ahead
        // waits to be written.
        h.push(b"STARTTLS\r\nEHLO\r\n")?;
        h.push(b"EHLO\r\n")?;
        h.allow_all()?;
        assert_eq!(h.take_output(), b"220 go ahead\r\n");
        let mut client = mail_client(client_config);
        for _ in 0..16 {
            h.push(&ciphertext(&mut client))?;
            decrypt(&mut client, &h.take_output());
        }
        assert!(!client.is_handshaking());
        // The session over TLS answers only what came over TLS.
        client.writer().write_all(b"EHLO\r\n")?;
        h.push(&ciphertext(&mut client))?;
        assert_eq!(
            decrypt(&mut client, &h.take_output()),
            b"250 hello tls=true sni=mail.test\r\n"
        );
        Ok(())
    }))
    .unwrap();
}

/// A careless session that keeps what the client pipelined after STARTTLS
/// still cannot pass it to TLS, whether it hands it over or stops taking
/// input and leaves it below: the switch drops it. Plaintext reaching TLS
/// would fail the handshake.
#[test]
fn a_careless_session_cannot_pass_pipelined_plaintext_to_tls() {
    let cases: [(Careless, &[&[u8]]); 3] = [
        (Careless::HandsOver, &[b"STARTTLS\r\nEHLO\r\n", b"EHLO\r\n"]),
        // The rest of the chunk handed back, then a chunk refused whole.
        (Careless::Refuses, &[b"STARTTLS\r\nEHLO\r\n"]),
        (Careless::Refuses, &[b"STARTTLS\r\n", b"EHLO\r\n"]),
    ];
    for (careless, pushes) in cases {
        block_on(lab(fictionet::Seed::from_u64(5), move |fcx| async move {
            let (config, client_config) = mail_configs(&fcx);
            let mut mail = Mail::plain(ConnInfo::default(), config, Duration::from_secs(10));
            mail.careless = Some(careless);
            let mut h = Harness::new(fictionet::Seed::from_u64(0), Starttls::new(mail))
                .with_worker(Polling::new());
            h.settle()?;
            h.take_output();
            h.withhold();
            for bytes in pushes {
                h.push(bytes)?;
            }
            h.allow_all()?;
            assert_eq!(h.take_output(), b"220 go ahead\r\n");
            assert!(h.layer().then().is_some());
            let mut client = mail_client(client_config);
            for _ in 0..16 {
                h.push(&ciphertext(&mut client))?;
                decrypt(&mut client, &h.take_output());
            }
            assert!(!client.is_handshaking());
            client.writer().write_all(b"EHLO\r\n")?;
            h.push(&ciphertext(&mut client))?;
            assert_eq!(
                decrypt(&mut client, &h.take_output()),
                b"250 hello tls=true sni=mail.test\r\n"
            );
            Ok(())
        }))
        .unwrap();
    }
}

/// After the go-ahead, bytes that are not a TLS handshake end the
/// connection with the TLS layer's failure.
#[test]
fn a_failed_starttls_handshake_ends_the_connection() {
    block_on(lab(fictionet::Seed::from_u64(3), |fcx| async move {
        let (config, _client_config) = mail_configs(&fcx);
        let mut h = starttls(config, Book::default());
        h.push(b"STARTTLS\r\n")?;
        assert!(h.layer().then().is_some());
        let failed = h.push(b"EHLO\r\nEHLO\r\nEHLO\r\n");
        assert!(
            matches!(failed, Err(Side::Upper(Side::Lower(_)))),
            "{failed:?}"
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn net_performs_starttls_for_a_session_that_asks() {
    let result = block_on(fictionet::lab(
        fictionet::Seed::from_u64(1),
        move |fcx| async move {
            let (config, roots) = tls_pair(&fcx, &["mail.test"]);
            let (attacher, attachments) = fictionet::attachments();
            let addr = Ipv4Addr::new(10, 40, 0, 25);
            let handshake = fictionet::stdlib::world::net::Limits::default().handshake;
            Net::new(fictionet_extras::network::cdn_pools())
                .ipv4_only()
                .host("mail", |h| {
                    h.at(addr)
                        .dns_name("mail.test")
                        .tcp_stack(25, move |conn: &ConnInfo| {
                            Starttls::new(Mail::plain(conn.clone(), config.clone(), handshake))
                        })
                })
                .start(&fcx, attachments)?;
            let s = machine(&fcx, attacher.attach("agent")?, ME);
            let mut tcp = s
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 25))
                .await?;
            assert_eq!(read_some(&fcx, &mut tcp, 16).await, b"220 mail ready\r\n");
            tcp.write_all(&fcx, b"STARTTLS\r\n").await?;
            assert_eq!(read_some(&fcx, &mut tcp, 14).await, b"220 go ahead\r\n");
            let mut tls = TlsClient::new(
                &fcx,
                tcp,
                &roots,
                "mail.test",
                &[],
                std::time::SystemTime::now(),
            )?;
            tls.handshake(&fcx).await?;
            tls.write_all(&fcx, b"EHLO\r\n").await?;
            let mut buf = [0u8; 128];
            let n = tls.read(&fcx, &mut buf).await?;
            assert_eq!(&buf[..n], b"250 hello tls=true sni=mail.test\r\n");
            Err::<(), fictionet::Error>(Done.into())
        },
    ));
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// A STARTTLS handshake has the handshake limit the session was given:
/// here the network's.
#[test]
fn net_limits_a_starttls_handshake() {
    fictionet_test_support::world::world(Duration::from_secs(60), move |fcx| async move {
        let (config, _roots) = tls_pair(&fcx, &["mail.test"]);
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 25);
        let limits = fictionet::stdlib::world::net::Limits {
            handshake: Duration::from_millis(200),
            ..Default::default()
        };
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .limits(limits)
            .host("mail", |h| {
                h.at(addr).tcp_stack(25, move |conn: &ConnInfo| {
                    Starttls::new(Mail::plain(conn.clone(), config.clone(), limits.handshake))
                })
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut conn = s
            .tcp
            .connect(&fcx, SocketAddr::new(addr.into(), 25))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 16).await, b"220 mail ready\r\n");
        conn.write_all(&fcx, b"STARTTLS\r\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 14).await, b"220 go ahead\r\n");
        // The client never starts its handshake.
        let started = fcx.now();
        assert_eq!(conn.read(&fcx, &mut [0; 1]).await?, 0);
        assert_eq!(
            fcx.now().since_start() - started.since_start(),
            Duration::from_millis(200)
        );
        Ok(())
    });
}
