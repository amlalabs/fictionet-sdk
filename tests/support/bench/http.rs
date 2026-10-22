mod observer;

use super::World;
use bytes::Bytes;
use fictionet_extras::hyper_io::{Exec, Io};
use fictionet::stdlib::protocols::dns::op::{MessageType, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{RData, RecordType};
use fictionet::stdlib::world::sandbox::{self, Machine, TlsClient};
use fictionet::stdlib::{network::Connection, services::tls, web};
use fictionet::{Attacher, Cx};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use observer::ObserverStatus;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

/// Returns a world socket path in the system temporary directory.
pub fn socket_path(tag: &str) -> std::path::PathBuf {
    static SOCKETS: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("fictionet-bench-sockets");
    std::fs::create_dir_all(&dir).unwrap();
    let n = SOCKETS.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("{tag}-{}-{n}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// CPU time this process has used, user and system, in microseconds.
fn cpu_us() -> u64 {
    let mut r = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given.
    let r = unsafe {
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr()), 0);
        r.assume_init()
    };
    ((r.ru_utime.tv_sec + r.ru_stime.tv_sec) * 1_000_000 + r.ru_utime.tv_usec + r.ru_stime.tv_usec)
        as u64
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)] as f64 / 1000.0
}

/// What a Sites run watches, through a real observer session.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Watch {
    None,
    /// A `watch` request: the graph and its changes.
    Graph,
    /// The graph, and a `packets` stream on every sandbox link.
    Packets,
    /// Packet streams with separate agent and bulk class budgets.
    Policy,
}

impl Watch {
    fn enabled(self) -> bool {
        self != Self::None
    }
}

struct LinkPolicy;
impl fictionet_observe::Policy for LinkPolicy {
    fn classes(&self) -> &[fictionet_observe::Class] {
        use fictionet_observe::Class;
        const CLASSES: &[Class] = &[
            Class::new("events").count(50_000).bytes(16 << 20).rank(3),
            Class::new("noise")
                .count(5_000)
                .bytes(2 << 20)
                .burst(64)
                .rank(1),
            Class::new("keys").count(20_000).bytes(8 << 20).rank(4),
            Class::new("agent").count(8_192).bytes(32 << 20).rank(2),
            Class::new("bulk")
                .watched()
                .count(4_096)
                .bytes(1 << 20)
                .snap(96)
                .burst(64),
        ];
        CLASSES
    }
    fn admit(&self, interest: fictionet::events::Interest<'_>) -> fictionet_observe::Admit {
        use fictionet::events::Interest;
        use fictionet::stdlib::network::ip;
        use fictionet_observe::Admit;
        match interest {
            Interest::Event(_, conn)
                if conn.sandbox.as_ref().is_some_and(|s| &*s.name == "jump") =>
            {
                Admit::Skip
            }
            Interest::Event(meta, _) if meta.source == "net" && meta.kind == "blocked" => {
                Admit::Class(1)
            }
            Interest::Event(..) | Interest::Topology(_) => Admit::Build,
            Interest::TlsKey(_) => Admit::Class(2),
            Interest::Packet(p) if p.sandbox == Some("jump") => Admit::Skip,
            Interest::Packet(p) if p.sandbox.is_some() => {
                match ip::Header::parse_truncated(p.bytes) {
                    Some(h)
                        if h.src == Ipv4Addr::new(10, 10, 5, 20)
                            || h.dst == Ipv4Addr::new(10, 10, 5, 20) =>
                    {
                        Admit::Skip
                    }
                    Some(h)
                        if h.src == Ipv4Addr::new(10, 10, 5, 30)
                            || h.dst == Ipv4Addr::new(10, 10, 5, 30) =>
                    {
                        Admit::Class(4)
                    }
                    _ => Admit::Class(3),
                }
            }
            Interest::Packet(_) => Admit::Class(4),
        }
    }
    fn sort(&self, observation: &fictionet::events::Observation<'_>) -> Option<usize> {
        match observation {
            fictionet::events::Observation::Event(event) => {
                Some(usize::from(event.repeat_fields().is_some()))
            }
            _ => None,
        }
    }
}

struct HttpRun {
    rps: f64,
    p50: f64,
    p99: f64,
    max: f64,
    cpu_per_request: f64,
    rows: u64,
}

#[derive(Clone, Copy)]
pub struct HttpCase {
    pub sandboxes: usize,
    pub h2: bool,
    pub requests: usize,
    pub body: usize,
    pub sites: usize,
    pub watch: Watch,
    /// Whether the world installs an observer that does nothing.
    pub hooks: bool,
    pub writer: bool,
}

#[derive(Clone)]
pub struct Page(pub Bytes);

impl tower_service::Service<Request<fictionet::stdlib::web::Body>> for Page {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<fictionet::stdlib::web::Body>) -> Self::Future {
        std::future::ready(Ok(Response::new(Full::new(self.0.clone()))))
    }
}

pub fn bench(bencher: divan::Bencher, case: HttpCase) {
    let result = Arc::new(Mutex::new(None));
    bencher
        .counter(divan::counter::ItemsCount::new(case.requests))
        .with_inputs(|| http_world(case, result.clone()))
        .bench_local_values(World::measure);
    if let Some(r) = result.lock().unwrap().take() {
        eprintln!(
            "last HTTP run: requests/s={:.0}, p50={:.1} us, p99={:.1} us, max={:.1} us, CPU={:.2} us/request, observer rows={}",
            r.rps, r.p50, r.p99, r.max, r.cpu_per_request, r.rows
        );
    }
}

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn machine(fcx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Machine {
    sandbox::machine(fcx, attacher.attach(name).unwrap(), addr)
}

async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> Ipv4Addr {
    let r = m
        .lookup(fcx, GATEWAY.into(), name, RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.metadata.message_type, MessageType::Response);
    assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{name}");
    r.answers
        .iter()
        .find_map(|rec| match &rec.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .expect("an A record")
}

fn certs(
    fcx: &Cx,
) -> (
    RootCertStore,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
) {
    use fictionet::stdlib::{
        protocols::x509::{Time, Validity},
        services::ca::Ca,
    };
    let ca = Ca::new(fcx, "benchmark CA").unwrap();
    let leaf = ca
        .issue(
            fcx,
            &["bench.test"],
            Validity {
                not_before: Time::from_unix(946684800).unwrap(),
                not_after: Time::from_unix(4102444800).unwrap(),
            },
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    (roots, leaf.chain, leaf.key)
}

/// One Sites world with `case.sandboxes` sandboxes, each holding one TLS
/// connection to `bench.test` and sending `case.requests / sandboxes`
/// requests on it, one at a time.
fn http_world(case: HttpCase, result: Arc<Mutex<Option<HttpRun>>>) -> World {
    let (attacher, attachments) = fictionet::attachments();
    // The observer reaches the world through an observation socket, as the
    // dashboard does.
    let path = socket_path("sites");
    let dashboard = case.watch.enabled().then(|| {
        let mut options = fictionet_observe::DashboardOptions::default();
        if case.watch == Watch::Policy {
            options.collector.policy = Arc::new(LinkPolicy);
        }
        fictionet_observe::DashboardObserver::new(options)
    });
    let listening = dashboard
        .as_ref()
        .map(|dashboard| fictionet_observe::serve(dashboard.handle(), &path).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Mutex::new(ObserverStatus::Waiting));
    let measuring = Arc::new(AtomicBool::new(false));
    let observer = Arc::new(Mutex::new(None));
    let watching = observer.clone();
    let watch_path = path.clone();
    let timing = measuring.clone();
    let stop_after = stop.clone();
    let wait_for = ready.clone();
    let mut options = fictionet::RunOptions::new(fictionet::Seed::random());
    struct Hook;
    impl fictionet::events::Observer for Hook {
        fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
            let fictionet::events::Interest::Event(_, _) = interest else {
                return false;
            };
            true
        }
        fn observe(&self, _: fictionet::events::Stamp, _: fictionet::events::Observation<'_>) {}
    }
    let writer = case.writer.then(|| {
        Arc::new(
            fictionet_observe::Jsonl::new(std::io::sink(), fictionet_observe::Limits::default())
                .unwrap(),
        )
    });
    let mut destinations: Vec<Arc<dyn fictionet::events::Observer>> = Vec::new();
    if let Some(dashboard) = &dashboard {
        destinations.push(dashboard.observer());
    }
    if let Some(writer) = &writer {
        destinations.push(writer.clone());
    }
    if case.hooks {
        destinations.push(Arc::new(Hook));
    }
    if !destinations.is_empty() {
        options = options.observer(Arc::new(fictionet::events::Fanout::new(destinations)));
    }
    let mut world = World::with_options(options, move |fcx, checkpoint| async move {
        let (roots, chain, key) = certs(&fcx);
        let roots = Arc::new(roots);
        let config = Arc::new(
            tls::config_builder(&fcx, SystemTime::now())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(chain, key)?,
        );
        let page = Page(Bytes::from(vec![b'x'; case.body]));
        let sites =
            web::Sites::new(move |_| Some(web::Site::new(page.clone()).tls(config.clone())));
        sites.start(&fcx, attachments)?;
        let machines: Vec<Machine> = (0..case.sandboxes)
            .map(|i| {
                machine(
                    &fcx,
                    &attacher,
                    &format!("sandbox{i}"),
                    Ipv4Addr::new(10, 0, 0, 2 + i as u8),
                )
            })
            .collect();
        let addr = lookup(&fcx, &machines[0], "bench.test").await;
        for i in 1..case.sites {
            lookup(&fcx, &machines[0], &format!("site{i}.test")).await;
        }
        // The DNS lookup has run the world and attached its graph.
        if case.watch.enabled() {
            *watching.lock().unwrap() = Some(std::thread::spawn(move || {
                let result = (|| {
                    let mut client = fictionet_observe::Client::connect(&watch_path)?;
                    client.set_timeout(Some(Duration::from_millis(100)))?;
                    observer::watch_world(
                        &mut client,
                        matches!(case.watch, Watch::Packets | Watch::Policy),
                        case.sandboxes,
                        &stop,
                        &ready,
                        &measuring,
                    )
                })();
                if let Err(error) = &result {
                    *ready.lock().unwrap() = ObserverStatus::Failed(error.to_string());
                }
                result
            }));
        }
        let mut clients = Vec::new();
        for m in &machines {
            let conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 443))
                .await?;
            let alpn: &[u8] = if case.h2 { b"h2" } else { b"http/1.1" };
            let mut t = TlsClient::new(
                &fcx,
                conn,
                &roots,
                "bench.test",
                &[alpn],
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_893_456_000),
            )
            .unwrap();
            t.handshake(&fcx)
                .await
                .map_err(|e| fictionet::Error::msg(format!("{e:?}")))?;
            let mut c = Client::new(&fcx, t, case.h2).await;
            for _ in 0..100 {
                c.get().await;
            }
            clients.push(c);
        }
        // Wait until the observer is watching, while the world runs.
        if case.watch.enabled() {
            while !wait_for.lock().unwrap().ready()? {
                fcx.sleep(fictionet::time::ms(5)).await?;
            }
        }
        let each = case.requests / case.sandboxes;
        let lat = Arc::new(Mutex::new(Vec::with_capacity(case.requests)));
        checkpoint.wait().await;
        let cpu0 = cpu_us();
        let start = Instant::now();
        timing.store(true, Ordering::Release);
        let mut tasks = Vec::new();
        for mut c in clients {
            let lat = lat.clone();
            tasks.push(fcx.spawn(move |_| async move {
                let mut samples = Vec::with_capacity(each);
                for _ in 0..each {
                    let t = Instant::now();
                    let (status, version, len) = c.get().await;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(len, case.body);
                    assert_eq!(
                        version,
                        if case.h2 {
                            Version::HTTP_2
                        } else {
                            Version::HTTP_11
                        }
                    );
                    samples.push(t.elapsed().as_nanos() as u64);
                }
                lat.lock().unwrap().extend(samples);
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&fcx).await?;
        }
        let secs = start.elapsed().as_secs_f64();
        let cpu1 = cpu_us() - cpu0;
        checkpoint.wait().await;
        // Rows still on their way belong to the timed requests.
        fcx.sleep(fictionet::time::ms(150)).await?;
        timing.store(false, Ordering::Release);
        stop_after.store(true, Ordering::Release);
        let mut l = lat.lock().unwrap();
        l.sort_unstable();
        let total = l.len();
        *result.lock().unwrap() = Some(HttpRun {
            rps: total as f64 / secs,
            p50: percentile(&l, 0.5),
            p99: percentile(&l, 0.99),
            max: percentile(&l, 1.0),
            cpu_per_request: cpu1 as f64 / total as f64,
            rows: 0,
        });
        drop(l);
        let observer = observer.lock().unwrap().take();
        let rows = observer
            .map_or(Ok(0), |o| o.join().expect("observer thread"))
            .expect("observer outlived the measurement");
        result.lock().unwrap().as_mut().unwrap().rows = rows;
        drop(listening);
        fcx.cancel();
        Ok(())
    });
    let future = std::mem::replace(&mut world.future, Box::pin(async { Ok(()) }));
    world.future = Box::pin(async move {
        let result = future.await;
        if let Some(writer) = writer {
            writer.finish()?;
        }
        result
    });
    world
}

// A hyper client over a `Connection`.

enum Client {
    H1(hyper::client::conn::http1::SendRequest<Empty<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Empty<Bytes>>),
}

impl Client {
    async fn new<C: Connection + Unpin>(fcx: &Cx, conn: C, h2: bool) -> Client {
        let io = Io {
            fcx: fcx.clone(),
            conn,
        };
        if h2 {
            let (send, conn) = hyper::client::conn::http2::handshake(Exec(fcx.clone()), io)
                .await
                .unwrap();
            fcx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H2(send)
        } else {
            let (send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            fcx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H1(send)
        }
    }

    /// GETs `https://bench.test/`: the status, the version and the body's
    /// length.
    async fn get(&mut self) -> (StatusCode, Version, usize) {
        let response = match self {
            Client::H1(s) => {
                s.ready().await.unwrap();
                let r = Request::builder()
                    .uri("/")
                    .header("host", "bench.test")
                    .body(Empty::new())
                    .unwrap();
                s.send_request(r).await.unwrap()
            }
            Client::H2(s) => {
                s.ready().await.unwrap();
                let r = Request::builder()
                    .uri("https://bench.test/")
                    .body(Empty::new())
                    .unwrap();
                s.send_request(r).await.unwrap()
            }
        };
        let (status, version) = (response.status(), response.version());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, version, body.len())
    }
}
