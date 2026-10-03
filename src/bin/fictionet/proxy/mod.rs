//! `fictionet attach --type https_proxy` and `--type socks5`: one proxy
//! engine with two doors.
//!
//! Attach runs next to the world, not in the sandbox. It listens on a TCP
//! port (`--listen`), and the sandbox's programs reach the world through
//! it, told by `HTTPS_PROXY` or `ALL_PROXY`. Each proxied connection
//! becomes IP packets from the sandbox's address (`--ip-addr`), made by
//! the SDK's userspace TCP/IP stack, so the world still sees only IP
//! packets. Names are looked up with the world's DNS server (`--dns`).
//!
//! The sandbox needs no privileges. What keeps the agent in is the
//! platform: the sandbox may reach attach's port and nothing else.

mod auth;
mod dns;
mod http;
mod link;
mod pump;
mod socks5;
mod stack;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::args::{ProxyArgs, ProxyKind};
use crate::world::{self, Failure, Greeting, err};
use auth::Token;
use link::Link;
use stack::Stack;

/// At most this many client connections at once. Each one may hold up to
/// 512 KiB of buffers in the stack while data moves.
const MAX_CLIENTS: usize = 1024;

/// Once the world is gone, clients still being served get this long to
/// finish. A client waiting for a connection hears why it failed (`503`,
/// or SOCKS5 reply 1) in that time, before attach exits.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// One line on stderr.
pub(crate) fn log(line: &str) {
    eprintln!("fictionet attach: {line}");
}

/// Runs a proxy type to the end. `Ok` means the world closed the
/// connection.
pub(crate) fn run(args: ProxyArgs) -> Result<(), Failure> {
    world::clear_ready_file(args.ready_file.as_deref());
    let token = Token::read(&args.token_file)?;
    // Client connections run on two worker threads, and the stack (inside
    // fictionet::run) on this one. With one thread for all of it, 50
    // downloads of 16 MiB at once took 2.8 to 3.1 s; with two workers,
    // 1.6 to 2.0 s.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .map_err(err("starting the runtime"))?;
    // Listen first, so a port that is taken stops attach before it says
    // hello. Clients that connect before the world accepts wait in the
    // listen queue.
    let std_listener = std::net::TcpListener::bind(args.listen).map_err(err(&format!("listening on {}", args.listen)))?;
    std_listener.set_nonblocking(true).map_err(err("making the listener nonblocking"))?;
    let listen = std_listener.local_addr().map_err(err("reading the listening address"))?;
    let sock = world::handshake(&Greeting {
        world: &args.world,
        world_wait: args.world_wait,
        kind: args.kind.name(),
        name: &args.name,
        mtu: 1500,
    })?;
    let door = match args.kind {
        ProxyKind::Http => "HTTP proxy",
        ProxyKind::Socks5 => "SOCKS5 proxy",
    };
    log(&format!("{} attached; {door} on {listen}, as {} with DNS at {}", args.name, args.ip_addr, args.dns));
    world::write_ready_file(args.ready_file.as_deref(), &args.name)?;

    let result = runtime.block_on(async move {
        let listener = TcpListener::from_std(std_listener).map_err(err("listening"))?;
        let link = Link::new(sock).map_err(err("watching the world's socket"))?;
        let shared = link.shared();
        let (ip, dns, kind) = (args.ip_addr, args.dns, args.kind);
        let limit = Arc::new(Semaphore::new(MAX_CLIENTS));
        let accepting: Arc<Mutex<Option<JoinHandle<()>>>> = Arc::default();
        let (limit2, accepting2) = (limit.clone(), accepting.clone());
        let ran = fictionet::run(move |cx| async move {
            let stack = Stack::new(&cx, link, ip, dns);
            *accepting2.lock().unwrap() = Some(tokio::spawn(accept(listener, stack, token, kind, limit2)));
            Ok(())
        })
        .await;
        // The stack has stopped, so no new connection can open. Stop
        // taking clients, which closes the port, and let the clients
        // already here finish. Each one holds a permit until it is done.
        // Returning sooner would drop the runtime, and with it a pending
        // 503 before it is written.
        if let Some(accepting) = accepting.lock().unwrap().take() {
            accepting.abort();
        }
        let _ = tokio::time::timeout(SHUTDOWN_GRACE, limit.acquire_many(MAX_CLIENTS as u32)).await;
        ran.map_err(|e| Failure::Error(format!("the stack stopped: {e}")))?;
        Ok::<_, Failure>(shared)
    });
    world::clear_ready_file(args.ready_file.as_deref());
    let shared = result?;
    if shared.dropped() > 0 {
        log(&format!("{} packets dropped on a full queue to the world", shared.dropped()));
    }
    match shared.error() {
        Some(why) => Err(Failure::Error(why)),
        None => {
            log("the world closed the connection; the proxy is closed");
            Ok(())
        }
    }
}

/// Takes client connections until it is aborted. Each client holds a
/// permit from `limit` while it is served.
async fn accept(listener: TcpListener, stack: Stack, token: Token, kind: ProxyKind, limit: Arc<Semaphore>) {
    loop {
        let client = match listener.accept().await {
            Ok((client, _)) => client,
            Err(e) => {
                // Out of file descriptors, most likely. Wait a moment
                // rather than spin.
                log(&format!("accepting a client: {e}"));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            tokio::spawn(busy(client, kind));
            continue;
        };
        let _ = client.set_nodelay(true);
        let (stack, token) = (stack.clone(), token.clone());
        tokio::spawn(async move {
            match kind {
                ProxyKind::Http => http::serve(client, stack, token).await,
                ProxyKind::Socks5 => socks5::serve(client, stack, token).await,
            }
            drop(permit);
        });
    }
}

/// Answers a client past [`MAX_CLIENTS`], then closes.
async fn busy(mut client: TcpStream, kind: ProxyKind) {
    use tokio::io::AsyncWriteExt;
    log(&format!("more than {MAX_CLIENTS} clients at once; one turned away"));
    if kind == ProxyKind::Http {
        let _ = client.write_all(&http::error_response(503, "too many connections through this proxy")).await;
    }
    let _ = client.shutdown().await;
}
