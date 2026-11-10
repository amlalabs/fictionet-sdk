//! What a stack and its work leave behind when their run is dropped,
//! cancelled or finished, and how a run ends when its connection's
//! shutdown waits, fails or is cancelled.

use crate::common::echo_stack::{Echo, Then};
use crate::common::line_stack::{DatagramApp, Datagrammed, LineApp, LineOut, Lined, Sends};

use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::codec::LineError;
use fictionet::stdlib::layer::{Budget, Harness, Switch};
use fictionet::stdlib::network::{ConnError, ConnInfo, Connection, tcp};
use fictionet::stdlib::services::stack::{
    self, Job, Polling, StackError, StreamEnd, StreamLimits, Tunnel,
};
use fictionet::{Cx, Seed};

/// Counts the work and stacks dropped.
#[derive(Default)]
struct Lifetime {
    work_dropped: AtomicUsize,
    stacks_dropped: AtomicUsize,
}

/// Work that never finishes.
struct RetainedWork(Arc<Lifetime>);

impl Job for RetainedWork {
    type Done = ();

    fn poll(&mut self, _: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for RetainedWork {
    fn drop(&mut self) {
        self.0.work_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// Starts two pieces of work that never finish as soon as it opens.
struct Retaining(Arc<Lifetime>);

impl LineApp for Retaining {
    type Timer = ();
    type Work = RetainedWork;
    type Done = ();
    type Next = Infallible;
    type Error = Infallible;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.start_in_order(RetainedWork(self.0.clone()));
        out.start(RetainedWork(self.0.clone()));
        Ok(())
    }

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        Ok(())
    }
}

impl Drop for Retaining {
    fn drop(&mut self) {
        self.0.stacks_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn dropping_a_harness_drops_the_stack_and_its_work() {
    let lifetime = Arc::new(Lifetime::default());
    let mut harness = Harness::new(Seed::from_u64(0), Lined::new(Retaining(lifetime.clone())))
        .with_worker(Polling::new());
    harness.settle().unwrap();
    assert_eq!(harness.jobs(), 2);
    assert_eq!(lifetime.work_dropped.load(Ordering::SeqCst), 0);
    drop(harness);
    assert_eq!(lifetime.work_dropped.load(Ordering::SeqCst), 2);
    assert_eq!(lifetime.stacks_dropped.load(Ordering::SeqCst), 1);
}

/// A connection that never sends and takes every write.
struct Idle;

impl Connection for Idle {
    fn poll_read(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Pending
    }
    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(Ok(data.len()))
    }
    fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn dropping_a_stream_run_drops_the_stack_and_its_work() {
    fictionet::block_on(fictionet::lab(Seed::from_u64(0), |fcx| async move {
        let lifetime = Arc::new(Lifetime::default());
        let stack = Lined::new(Retaining(lifetime.clone()));
        let info = ConnInfo::default();
        let (budget, limits) = (Budget::unlimited(), StreamLimits::default());
        let mut run = Box::pin(stack::stream(
            &fcx,
            Idle,
            &info,
            stack,
            budget,
            limits,
            |_| {},
        ));
        poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(lifetime.work_dropped.load(Ordering::SeqCst), 0);
        drop(run);
        assert_eq!(lifetime.work_dropped.load(Ordering::SeqCst), 2);
        assert_eq!(lifetime.stacks_dropped.load(Ordering::SeqCst), 1);
        Ok(())
    }))
    .unwrap();
}

impl fictionet::stdlib::network::DatagramSocket for Idle {
    async fn recv(&mut self, _: &Cx) -> Result<(Vec<u8>, SocketAddr), fictionet::RecvError> {
        std::future::pending().await
    }
    fn send_to(&mut self, _: &[u8], _: SocketAddr) {}
}

/// Answers nothing, and counts its drop.
struct Silent(Arc<Lifetime>);

impl DatagramApp for Silent {
    type Timer = ();

    fn line(&mut self, _: Result<Vec<u8>, LineError>, _: SocketAddr, _: &mut Sends<'_, ()>) {}
}

impl Drop for Silent {
    fn drop(&mut self) {
        self.0.stacks_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn dropping_a_datagram_run_drops_the_stack() {
    fictionet::block_on(fictionet::lab(Seed::from_u64(0), |fcx| async move {
        let lifetime = Arc::new(Lifetime::default());
        let local: SocketAddr = "127.0.0.1:7".parse()?;
        let stack = Datagrammed::new(Silent(lifetime.clone()), Some(local));
        let mut run = Box::pin(stack::datagrams(
            &fcx,
            Idle,
            local,
            stack,
            Budget::unlimited(),
            |_| {},
        ));
        poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(lifetime.stacks_dropped.load(Ordering::SeqCst), 0);
        drop(run);
        assert_eq!(lifetime.stacks_dropped.load(Ordering::SeqCst), 1);
        Ok(())
    }))
    .unwrap();
}

/// Work that never finishes and cancels its own region the first time it
/// is polled, as a stdlib timeout inside work may.
struct CancelsItself(bool);

impl Job for CancelsItself {
    type Done = ();

    fn poll(&mut self, fcx: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            if let Some(fcx) = fcx {
                fcx.cancel();
            }
            self.0 = false;
        }
        Poll::Pending
    }
}

/// Closes on its first line, and starts work that writes a goodbye
/// later, which it never does.
struct Goodbye;

impl LineApp for Goodbye {
    type Timer = ();
    type Work = CancelsItself;
    type Done = ();
    type Next = Infallible;
    type Error = Infallible;

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        out.start(CancelsItself(true));
        out.close();
        Ok(())
    }
}

#[test]
fn work_that_cancels_its_own_region_keeps_the_world_running() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
            let (a, b) = fictionet::pair();
            let client = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
            let server = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
            crate::common::line_stack::listen(
                &fcx,
                server.listen(7)?,
                StreamLimits::default(),
                || Lined::new(Goodbye),
            );
            let mut conn = client.connect(&fcx, "10.0.0.1:7".parse()?).await?;
            conn.write_all(&fcx, b"bye\n").await?;
            assert_eq!(conn.read(&fcx, &mut [0; 1]).await?, 0);
            fcx.cancel();
            Ok(())
        }));
        let _ = tx.send(r.map_err(|e| e.to_string()));
    });
    rx.recv_timeout(Duration::from_secs(20))
        .expect("lab finishes")
        .expect("the world survives work cancelling its own region");
}

/// Work that spawns a task waiting for its cancel, and finishes at once.
struct SpawnWork(Arc<AtomicBool>);

impl Job for SpawnWork {
    type Done = ();

    fn poll(&mut self, fcx: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
        let stopped = self.0.clone();
        fcx.expect("a world").spawn(move |fcx| async move {
            fcx.cancelled().await;
            stopped.store(true, Ordering::SeqCst);
            Ok(())
        });
        Poll::Ready(())
    }
}

/// Starts work that spawns a task on its first line, and closes.
struct Spawning(Arc<AtomicBool>);

impl LineApp for Spawning {
    type Timer = ();
    type Work = SpawnWork;
    type Done = ();
    type Next = Infallible;
    type Error = Infallible;

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        out.start(SpawnWork(self.0.clone()));
        out.close();
        Ok(())
    }
}

#[test]
fn finishing_a_run_cancels_and_joins_its_spawned_work() {
    fictionet::block_on(fictionet::lab(Seed::from_u64(2), |fcx| async move {
        let (a, b) = fictionet::pair();
        let client = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
        let server = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
        let mut listener = server.listen(7)?;
        fcx.spawn(move |fcx| async move {
            let mut conn = client.connect(&fcx, "10.0.0.1:7".parse()?).await?;
            conn.write_all(&fcx, b"bye\n").await?;
            fcx.cancelled().await;
            Ok(())
        });
        let conn = listener.accept(&fcx).await?;
        let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
        let stopped = Arc::new(AtomicBool::new(false));
        let stack = Lined::new(Spawning(stopped.clone()));
        let (budget, limits) = (Budget::unlimited(), StreamLimits::default());
        let ended = stack::stream(&fcx, conn, &info, stack, budget, limits, |_| {}).await;
        assert!(matches!(ended, Ok(StreamEnd::Finished)), "{ended:?}");
        assert!(stopped.load(Ordering::SeqCst));
        assert!(!fcx.is_cancelled());
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// Work that spawns a task that fails, and never finishes itself.
struct BackgroundFailure(bool);

impl Job for BackgroundFailure {
    type Done = ();

    fn poll(&mut self, fcx: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
        if !self.0 {
            fcx.expect("a world")
                .spawn(|_| async { Err(fictionet::Error::msg("boom")) });
            self.0 = true;
        }
        Poll::Pending
    }
}

/// A stack over a connection with nothing to read: it may fail as it
/// opens, may start failing work, and counts how often it heard the end.
#[derive(Default)]
struct Terminal {
    background: bool,
    fail: bool,
    ended: Arc<AtomicUsize>,
}

impl LineApp for Terminal {
    type Timer = ();
    type Work = BackgroundFailure;
    type Done = ();
    type Next = Infallible;
    type Error = std::io::Error;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), std::io::Error> {
        if self.background {
            out.start(BackgroundFailure(false));
        }
        if self.fail {
            return Err(std::io::Error::other("the stack failed first"));
        }
        Ok(())
    }

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &mut LineOut<'_, Self>,
    ) -> Result<(), std::io::Error> {
        panic!("the terminal connection sends no lines")
    }

    fn ended(&mut self, _: &mut LineOut<'_, Self>) -> Result<(), std::io::Error> {
        self.ended.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Shutdown {
    Ready(Result<(), ConnError>),
    Pending,
    PendingUntilCancelled,
}

/// A connection whose peer has already sent everything, and whose
/// shutdown behaves as `shutdown` says.
struct TerminalConn {
    shutdown: Shutdown,
    polled: Arc<std::sync::Mutex<Option<Cx>>>,
}

impl Connection for TerminalConn {
    fn poll_read(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(Ok(0))
    }

    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        panic!("these stacks write nothing")
    }

    fn poll_shutdown(&mut self, fcx: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        *self.polled.lock().unwrap() = Some(fcx.clone());
        match self.shutdown {
            Shutdown::Ready(result) => Poll::Ready(result),
            Shutdown::PendingUntilCancelled if fcx.is_cancelled() => {
                Poll::Ready(Err(ConnError::Cancelled))
            }
            Shutdown::Pending | Shutdown::PendingUntilCancelled => Poll::Pending,
        }
    }
}

/// Runs a [`Terminal`] over a [`TerminalConn`] with `shutdown`.
fn terminal_run(
    stack: Terminal,
    shutdown: Shutdown,
    cancel: bool,
) -> (
    Result<StreamEnd, StackError<String>>,
    Duration,
    Arc<AtomicUsize>,
) {
    let ended = stack.ended.clone();
    let out = Arc::new(std::sync::Mutex::new(None));
    let slot = out.clone();
    fictionet::block_on(fictionet::lab(Seed::from_u64(4), move |fcx| async move {
        let polled = Arc::new(std::sync::Mutex::new(None));
        let conn = TerminalConn {
            shutdown,
            polled: polled.clone(),
        };
        let info = ConnInfo::new(42, "10.0.0.1:7".parse()?, "10.0.0.2:1234".parse()?);
        let started = fcx.now();
        let (budget, limits) = (Budget::unlimited(), StreamLimits::default());
        let result = {
            let mut run = std::pin::pin!(stack::stream(
                &fcx,
                conn,
                &info,
                Lined::new(stack),
                budget,
                limits,
                |_| {}
            ));
            poll_fn(|cx| {
                let result = run.as_mut().poll(cx);
                if result.is_pending()
                    && cancel
                    && let Some(region) = polled.lock().unwrap().take()
                {
                    // Cancel only once shutdown has actually waited.
                    region.cancel();
                }
                result
            })
            .await
        };
        let took = fcx.now().since_start() - started.since_start();
        let result = result.map_err(|e| match e {
            StackError::Layer(e) => StackError::Layer(fictionet::ErrorChain(&e).to_string()),
            StackError::Cancelled => StackError::Cancelled,
        });
        assert!(!fcx.is_cancelled(), "the caller's region is untouched");
        *slot.lock().unwrap() = Some((result, took));
        Ok(())
    }))
    .unwrap();
    let (result, took) = out.lock().unwrap().take().expect("the run ended");
    (result, took, ended)
}

/// A task of the stack's work that fails ends that work and the run, as a
/// cancel of the run's region, and leaves the caller's region alone. Before,
/// work whose task failed was polled for ever and the run never ended.
#[test]
fn a_background_failure_ends_the_run_and_spares_the_caller() {
    let stack = Terminal {
        background: true,
        ..Terminal::default()
    };
    let (result, _, _) = terminal_run(stack, Shutdown::Ready(Ok(())), false);
    assert!(matches!(result, Err(StackError::Cancelled)), "{result:?}");
}

#[test]
fn a_stack_error_stays_primary_when_background_work_fails() {
    let stack = Terminal {
        background: true,
        fail: true,
        ..Terminal::default()
    };
    let (result, _, ended) = terminal_run(stack, Shutdown::Ready(Ok(())), false);
    match result {
        Err(StackError::Layer(e)) => assert!(e.contains("the stack failed first"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ended.load(Ordering::SeqCst),
        0,
        "a failed stack hears nothing more"
    );
}

#[test]
fn a_shutdown_cancelled_while_it_waits_returns_the_cancel() {
    for shutdown in [Shutdown::Pending, Shutdown::PendingUntilCancelled] {
        let (result, _, ended) = terminal_run(Terminal::default(), shutdown, true);
        assert!(matches!(result, Err(StackError::Cancelled)), "{result:?}");
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "the stack heard the end once"
        );
    }
}

#[test]
fn a_shutdown_that_never_finishes_times_out() {
    let (result, took, ended) = terminal_run(Terminal::default(), Shutdown::Pending, false);
    assert!(
        matches!(result, Ok(StreamEnd::Conn(ConnError::TimedOut))),
        "{result:?}"
    );
    assert_eq!(took, StreamLimits::default().write_timeout.unwrap());
    assert_eq!(ended.load(Ordering::SeqCst), 1);
}

#[test]
fn a_shutdown_that_fails_ends_the_run_with_its_error() {
    for error in [
        ConnError::Reset,
        ConnError::Closed,
        ConnError::TimedOut,
        ConnError::Broken,
    ] {
        let (result, _, ended) =
            terminal_run(Terminal::default(), Shutdown::Ready(Err(error)), false);
        assert!(
            matches!(result, Ok(StreamEnd::Conn(e)) if e == error),
            "{error:?}: {result:?}"
        );
        assert_eq!(ended.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn a_stack_error_stays_primary_when_shutdown_is_cancelled() {
    let stack = Terminal {
        fail: true,
        ..Terminal::default()
    };
    let (result, _, _) = terminal_run(stack, Shutdown::Pending, true);
    assert!(matches!(result, Err(StackError::Layer(_))), "{result:?}");
}

#[test]
fn a_successful_shutdown_finishes_the_run() {
    let (result, _, ended) = terminal_run(Terminal::default(), Shutdown::Ready(Ok(())), false);
    assert!(matches!(result, Ok(StreamEnd::Finished)), "{result:?}");
    assert_eq!(ended.load(Ordering::SeqCst), 1);
}

/// A connection that hands the runner every byte at once and cancels the
/// run's region as it does: a stop that lands between reads.
struct Feed(Option<Vec<u8>>);

impl Connection for Feed {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        let Some(bytes) = self.0.take() else {
            return Poll::Pending;
        };
        fcx.cancel();
        let n = buf.len().min(bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        if n < bytes.len() {
            self.0 = Some(bytes[n..].to_vec());
        }
        Poll::Ready(Ok(n))
    }
    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(Ok(data.len()))
    }
    fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        Poll::Ready(Ok(()))
    }
}

/// Once the run's region is cancelled, nothing is handed on: the run
/// returns the cancel, however many lines come before the handover, and
/// the next protocol's code never runs.
#[test]
fn a_cancelled_region_hands_no_connection_off() {
    for lines in 0..70 {
        let mut input = b"x\n".repeat(lines);
        input.extend_from_slice(b"handoff\n");
        let took_over = Arc::new(AtomicBool::new(false));
        let flag = took_over.clone();
        let then: Then = Arc::new(move || {
            let flag = flag.clone();
            Tunnel::new(move |_, _| async move { flag.store(true, Ordering::SeqCst) })
        });
        let served = Arc::new(std::sync::Mutex::new(None));
        let slot = served.clone();
        fictionet::block_on(fictionet::lab(Seed::from_u64(0), |fcx| async move {
            let stack: Switch<Lined<Echo>, Tunnel> =
                Switch::new(Lined::new(Echo { then: Some(then) }));
            let (budget, limits) = (Budget::unlimited(), StreamLimits::default());
            let info = ConnInfo::default();
            let result = stack::stream(
                &fcx,
                Feed(Some(input)),
                &info,
                stack,
                budget,
                limits,
                |_| {},
            )
            .await;
            *slot.lock().unwrap() = Some(matches!(result, Err(StackError::Cancelled)));
            Ok(())
        }))
        .unwrap();
        assert_eq!(
            served.lock().unwrap().take(),
            Some(true),
            "{lines} lines before the handover"
        );
        assert!(
            !took_over.load(Ordering::SeqCst),
            "{lines} lines before the handover"
        );
    }
}
