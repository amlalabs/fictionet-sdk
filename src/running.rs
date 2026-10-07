//! Running a world: the program around it, how it starts and stops, and how
//! to run one in a test.
//!
//! A world is an async function (see [A world in code](crate#a-world-in-code)).
//! This page shows the small `main` that runs it for real sandboxes, explains
//! each call, and then shows how a test runs the same world with no socket
//! and no `fictionet attach`. To run a world now, with real commands, start
//! with [`getting_started`](crate::getting_started).
//!
//! # The program
//!
//! Fictionet does not own `main` or the executor. A world runs inside an
//! ordinary Rust program, and that program makes four calls. This is all of
//! `main`:
//!
//! ```no_run
//! # use fictionet::{Attachments, Cx, Result};
//! # async fn world(_fcx: Cx, _attachments: Attachments, _args: Vec<String>) -> Result { Ok(()) }
//! fn main() -> fictionet::Result {
//!     // 1. A channel for sandboxes.
//!     let (attacher, attachments) = fictionet::attachments();
//!
//!     // 2. The world socket. Each `fictionet attach` that connects to it
//!     //    arrives through `attacher`.
//!     let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
//!     let _listening = fictionet::listen(socket, attacher)?;
//!
//!     // 3. The world, as one future. Nothing runs yet.
//!     let args: Vec<String> = std::env::args().skip(1).collect();
//!     let world = fictionet::run(move |fcx| world(fcx, attachments, args));
//!
//!     // 4. Poll that future on this thread until the world ends.
//!     fictionet::block_on(world)
//! }
//! ```
//!
#![doc = include_str!("../docs/diagrams/running.svg")]
//!
//! Here is what each call does:
//!
//! 1. **[`attachments()`](crate::attachments)** makes a channel with two
//!    halves. The [`Attacher`](crate::Attacher) adds sandboxes, and the
//!    [`Attachments`](crate::Attachments) hands them to the world, by name
//!    or in the order they arrive. Nothing is connected yet.
//! 2. **[`listen(socket, attacher)`](crate::listen)** makes the Unix socket
//!    that `socket` names and starts one helper thread. A
//!    [`WorldSocket`](crate::WorldSocket) is a world socket's address, such
//!    as `unix:/run/fictionet/world.sock`, the same form attach's `--world`
//!    flag takes. `listen` returns immediately, and the helper thread does
//!    the rest in the background. Each `fictionet attach` that connects
//!    first sends the sandbox's name. The helper accepts it, or refuses it
//!    if that name is already attached ([the relay protocol](crate::proto)
//!    has the messages). Each accepted sandbox goes into the channel as an
//!    [`Attachment`](crate::Attachment). Keep the returned
//!    [`Listening`](crate::Listening) in a named variable. Dropping it
//!    closes the socket, and `let _ = listen(...)` drops it on the spot.
//! 3. **[`run(f)`](crate::run)** returns a future and does nothing else.
//!    When the future is first polled, it makes the world's
//!    [`Cx`](crate::Cx) and starts `f(fcx)` as the first task. Every task the
//!    world starts with [`Cx::spawn`](crate::Cx::spawn), and every stdlib
//!    task, is polled inside this same future.
//! 4. **[`block_on`](crate::block_on)** polls the future on the current
//!    thread, and sleeps while there is nothing to do. The helper threads
//!    wake it when a packet arrives or a timer is due.
//!
//! The world process has the host's real network, so world code can also
//! reach the internet or a database. There is no central daemon: each world
//! is its own process.
//!
//! Inside the world, [`attachments.get(&fcx, "agent")`](crate::Attachments::get)
//! `.await` waits until the
//! sandbox named `agent` attaches, and returns its `Attachment`. A world can
//! also take every sandbox as it arrives, as the `ping_world` example does:
//!
//! ```
//! # use fictionet::{Attachment, Attachments, Cx, Result};
//! # async fn serve(_fcx: Cx, _sandbox: Attachment) -> Result { Ok(()) }
//! # async fn world(fcx: Cx, mut attachments: Attachments) -> Result {
//! loop {
//!     let sandbox = attachments.next(&fcx).await?;
//!     fcx.spawn(move |fcx| serve(fcx, sandbox));
//! }
//! # }
//! ```
//!
//! When the world stops, `next` returns [`Cancelled`](crate::Cancelled),
//! and `?` ends the loop with it. That is not a failure: see
//! [What ends what](#what-ends-what).
//!
//! # How long it runs, and how it stops
//!
//! A world function usually wires up its network and returns `Ok(())`. The
//! tasks it started keep running, and the future from `run` finishes only
//! when all of them have ended. So a world that serves sandboxes runs until
//! something stops it: an error, a deliberate cancel, or the process
//! ending.
//!
//! Fictionet installs no signal handlers in the world process, so Ctrl-C or
//! SIGTERM ends it as usual. The kernel then closes every connection on the
//! world socket. Each `fictionet attach` sees the world close its
//! connection, closes its device or proxy port (a `tun0` goes away with
//! it), and exits with status 0.
//!
//! ## What ends what
//!
//! Every task belongs to a [region](crate::Cx#regions). The world function
//! and every task it spawns share the region that `run` makes. No task
//! outlives its region. This table lists each way something in a world can end, and
//! what happens to the rest:
//!
//! | When | What happens | Why |
//! |---|---|---|
//! | The world function returns `Ok` | Nothing stops. The tasks it started keep running, and `run` finishes once the last of them has ended. | Returning `Ok` does not cancel a region. This is how a world wires its network and leaves it running. |
//! | The world function returns `Err` | The world's region is cancelled. Every task stops at its next wait, and `run` returns the error once they have all ended. | An error fails the region of the task that returned it. The world function is the first task in the world's region. |
//! | A spawned task returns `Err` | The same: the whole world stops, and `run` returns that error. [`Task::join`](crate::Task::join) on that task returns the same error, shared, as [`JoinError::Failed`](crate::JoinError::Failed). | The task shares the world's region, so a failure deep inside a world reaches the harness. Work that is allowed to fail handles its own errors and returns `Ok(())`. Stdlib code does this for work such as one HTTP connection, which runs in a region of its own inside the world's. |
//! | A task returns [`Cancelled`](crate::Cancelled), or an error whose `Cancelled` variant says a wait was cancelled | Nothing else stops. The region keeps no error and is not cancelled. `Task::join` on that task returns [`JoinError::Cancelled`](crate::JoinError::Cancelled). | The task ended because a region was cancelled, its own or that of a `Cx` it waited on. A cancel is not a failure. |
//! | A task panics | The panic is not caught. It unwinds out of the future from `run`, and the run ends there, as when the future is dropped. | A panic is a bug in the world, and the world's author handles it. Nothing in Fictionet catches it to keep the world running. |
//! | A [`Task`](crate::Task) handle is dropped | Nothing. The task is detached and keeps running. | The region owns the task, not the handle. |
//! | A sandbox detaches | Its [`Attachment`](crate::Attachment) hands over the packets that already arrived, and then `recv` returns [`RecvError::Closed`](crate::RecvError::Closed). Packets sent to it are dropped. Stdlib tasks that read it each stop by their own rule, listed under [Three kinds of functions](crate::stdlib#three-kinds-of-functions). A [`delay`](crate::stdlib::delay), [`bottleneck`](crate::stdlib::bottleneck) or [`filter`](crate::stdlib::filter) stops as soon as either of its interfaces closes. A `filter` has passed on every packet by then, but packets that a `delay` or `bottleneck` still holds are lost, so a detach can cut off the packets in flight in a pipeline. The sandbox's name is free to attach again. | A detach closes an interface. It is not an error, so the region is not cancelled. A task of your own that passes `Closed` up with `?` does fail the world, so a world that should outlive one sandbox ends that loop on `Closed` instead. |
//! | The future from `run` is dropped | Everything stops immediately. The tasks are dropped without being polled again, so their own code gets no chance to clean up. A wait outside the run, such as in a tokio task, returns [`Cancelled`](crate::Cancelled) if it waited on a clone of one of the run's `Cx`s, or [`RecvError::Closed`](crate::RecvError::Closed) if it waited on an interface whose other end was inside the run. `Task::join` on a task that had not ended returns `Cancelled`. | Dropping a future is how Rust abandons work, for example when a timeout around it fires. |
//! | A region is cancelled, by [`Cx::cancel`](crate::Cx::cancel) or by an error | Every Fictionet wait in the region returns `Cancelled`, and each task ends through its own code. Regions inside it are cancelled too. The region ends when its last task ends. After an error, `run` returns that error. After `Cx::cancel`, it returns `Ok(())`, unless a task failed before the cancel. A region made with [`Cx::region`](crate::Cx::region) that was cancelled because the region around it was returns `Cancelled`. | Cancellation is cooperative, as the next section explains. |
//!
//! ## Cancellation is cooperative
//!
//! A cancel does not drop a task. It wakes the task, and the task stops at
//! its next await on a Fictionet future: [`recv`](crate::InterfaceExt::recv),
//! [`Cx::sleep`](crate::Cx::sleep), [`Attachments::next`](crate::Attachments::next),
//! a stdlib connection's read, and the rest. Each of these returns `Err`,
//! with [`Cancelled`](crate::Cancelled) itself or with its own error type's
//! `Cancelled` variant, such as [`RecvError::Cancelled`](crate::RecvError::Cancelled).
//! A cancel is never `None`, `Ok`, or another error such as a broken
//! connection, and it comes before anything the wait already holds, such
//! as queued packets. The task usually passes it up with `?`.
//!
//! An await on anything outside Fictionet is not interrupted. A task that
//! waits on a tokio socket, a database query or a channel keeps waiting
//! after the cancel, and its region stays open until that wait ends. Such a
//! task races the wait against [`Cx::cancelled`](crate::Cx::cancelled),
//! which finishes when the region is cancelled. This task reads a feed from
//! a real TCP connection, and stops either when the feed ends or when its
//! region is cancelled:
//!
//! ```
//! use fictionet::{Cx, Result};
//! use tokio::io::AsyncReadExt;
//!
//! async fn read_feed(fcx: Cx, mut feed: tokio::net::TcpStream) -> Result {
//!     let mut buf = vec![0; 4096];
//!     loop {
//!         tokio::select! {
//!             n = feed.read(&mut buf) => {
//!                 let n = n?;
//!                 if n == 0 {
//!                     return Ok(()); // the feed ended
//!                 }
//!                 // use buf[..n]
//!             }
//!             _ = fcx.cancelled() => return Ok(()), // the region was cancelled
//!         }
//!     }
//! }
//! ```
//!
//! `tokio::select!` needs tokio's `macros` feature in your own
//! `Cargo.toml`, and a tokio socket needs `run` polled on a tokio runtime
//! (see [On tokio](#on-tokio)). Code that blocks the thread, such as a
//! `std::net` read, cannot be raced at all: it stops every task in the run
//! until it returns. Move it to a thread of its own with
//! `std::thread::spawn`, send the result back over a channel, and race the
//! channel against `fcx.cancelled()`. The thread itself keeps running until
//! the call returns, so give the call a time limit of its own, such as
//! `TcpStream::set_read_timeout`. Avoid tokio's `spawn_blocking` for this:
//! a tokio runtime waits for its blocking calls when it shuts down, so one
//! that never returns keeps the test from ending.
//!
//! # Starting things in order
//!
//! Three things start in a fixed order, because each one needs the one
//! before it:
//!
//! 1. **The world.** `listen` makes the socket, but not its directory, so
//!    make `/run/fictionet` before the world starts. An attach started
//!    before the socket exists exits with status 1, unless it was given
//!    `--world-wait <seconds>`, which makes it keep trying for that long.
//! 2. **Attach,** one per sandbox. It sets up the sandbox's network. Once
//!    the world has accepted the sandbox, it creates the file named with
//!    `--ready-file <path>`, if you gave one.
//! 3. **The agent,** once the ready file exists. The ready file says that
//!    the sandbox's network is set up, not that the world answers yet:
//!    [Readiness](crate::getting_started#readiness) shows how to check
//!    that end to end.
//!
//! The [Docker Compose setup](crate::attaching#in-docker-compose) does this
//! with `depends_on`: attach starts once the world's container has
//! started, waits for the socket with `--world-wait`, and its healthcheck
//! runs `fictionet ready` on the ready file. The agent starts once that
//! healthcheck passes.
//!
//! # On tokio
//!
//! [`block_on`](crate::block_on) is not a tokio runtime. A world that uses
//! the `tokio` feature (such as `web::proxy()`, which passes requests to a
//! real site), or a tokio-based library
//! such as a database client, polls `run` on a tokio runtime instead. Steps
//! 1 to 3 stay the same. The `web_world` example does this:
//!
//! ```no_run
//! # use fictionet::{Attachments, Cx, Result};
//! # async fn world(_fcx: Cx, _attachments: Attachments) -> Result { Ok(()) }
//! # fn main() -> Result {
//! # let (_attacher, attachments) = fictionet::attachments();
//! let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
//! runtime.block_on(fictionet::run(move |fcx| world(fcx, attachments)))
//! # }
//! ```
//!
//! # In a test
//!
//! A test can run a world with no socket and no `fictionet attach`. It skips
//! `listen`, keeps the `Attacher` for itself, and plays the sandbox.
//! [`Attacher::attach`](crate::Attacher::attach) returns the sandbox's end of
//! a [`pair`](crate::pair), and the world gets the other end as the
//! `Attachment`. The test sends raw IP packets into its end, and reads what
//! the world sends back.
//!
//! A world under test runs until something stops it, so the test needs two
//! things: a clean way to stop the world when the checks pass, and a time
//! limit in case they never finish. In this example, the world under test
//! echoes every packet. The test sends one packet, checks that it comes
//! back, and then calls [`Cx::cancel`](crate::Cx::cancel). A tokio timeout
//! around the whole run bounds the test at 10 seconds:
//!
//! ```
//! use std::time::Duration;
//! use fictionet::prelude::*;
//! use fictionet::{Attachments, Cx, Interface, Packet, Result};
//!
//! /// The world under test: it sends every packet from "agent" straight back.
//! async fn world(fcx: Cx, mut attachments: Attachments) -> Result {
//!     let mut agent = attachments.get(&fcx, "agent").await?;
//!     while let Ok(packet) = agent.recv(&fcx).await {
//!         agent.send(packet);
//!     }
//!     Ok(())
//! }
//!
//! let (attacher, attachments) = fictionet::attachments();
//! // The test plays the sandbox "agent": it holds the sandbox's end.
//! let mut agent = attacher.attach("agent").unwrap();
//!
//! let test = fictionet::run(move |fcx| async move {
//!     fcx.spawn(move |fcx| world(fcx, attachments));
//!     agent.send(Packet(vec![0x45, 0, 0, 20]));
//!     assert_eq!(agent.recv(&fcx).await?, Packet(vec![0x45, 0, 0, 20]));
//!     // The checks passed. Stop the world, and every task in it.
//!     fcx.cancel();
//!     Ok(())
//! });
//!
//! let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
//! let result = runtime.block_on(async { tokio::time::timeout(Duration::from_secs(10), test).await });
//! result.expect("the test timed out").expect("the world failed");
//! ```
//!
//! The test's code runs inside the same `run` as the world, as one more
//! task. Both are polled on one thread, taking turns. The three outcomes
//! stay apart:
//!
//! - **The checks pass.** `fcx.cancel()` stops the world cleanly. Each task
//!   ends through its own code, and `run` returns `Ok(())`. The `Cancelled`
//!   that a task passes up with `?` is never a failure, and other errors
//!   that tasks return after the cancel are not reported either. A task
//!   whose cleanup can fail in a way the test must see reports it before
//!   the test cancels, or through a channel the test reads.
//! - **The world fails.** A task's error cancels the world's region, and
//!   `run` returns that error, so the test fails with the world's own
//!   message. A failed `assert!` in the test's code panics, and the panic
//!   fails the test the same way.
//! - **Something never finishes.** The timeout fires and drops the future
//!   from `run`, which stops every task immediately (see
//!   [What ends what](#what-ends-what)). The timeout sits outside the run,
//!   so it also covers a world that ignores the cancel, such as one stuck
//!   in a wait on a tokio socket. It cannot interrupt code that blocks the
//!   thread, since the timer runs on that same thread.
//!
//! Stopping the world with an error instead, such as `Err("done")`, makes
//! every test end in `Err`. A real failure in the world then looks like the
//! expected end, unless every test compares error strings.
//!
//! Time is real time, so a test that depends on exact timing can be flaky.
//! A simulated clock for tests is on the [roadmap](crate::roadmap#the-lab),
//! along with running worlds from the `fictionet` binary and from Python.
