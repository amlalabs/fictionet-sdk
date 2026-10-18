use fictionet::RunOptions;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::stdlib::network::tcp;
use fictionet::stdlib::network::{ConnError, Connection};
use fictionet::stdlib::services::serve::{self, Flow, Pending, PendingDriver};
use fictionet::time::ms;

/// Work that never finishes.
struct Forever(bool);
impl Pending for Forever {
    fn poll_next(
        &mut self,
        d: &mut PendingDriver<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        if self.0 {
            // Cancel only this connection, as a service or a stdlib
            // timeout may.
            if let Some(fcx) = d.fcx() {
                fcx.cancel();
            }
            self.0 = false;
        }
        Poll::Pending
    }
}

struct Svc;
service_fixture! {
    Svc => (Lines, (), std::convert::Infallible);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_item(self, _line: Result<Vec<u8>, LineError>; _, _driver) -> Flow {
        Ok(Flow::Close)
    }
    on_end(self, _end: serve::Ended; _, driver) -> () {
        // A goodbye written by deferred work: Ending, with ordered work.
        driver.defer(Forever(true));
        Ok(())
    }
}

#[test]
fn cancelling_deferred_end_work_keeps_the_world_running() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = fictionet::block_on(crate::common::observed_lab(
            fictionet::Seed::from_u64(1),
            |fcx, evidence| async move {
                let (a, b) = fictionet::pair();
                let client = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
                let server = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
                serve::listen(
                    &fcx,
                    server.listen(7)?,
                    Arc::new(()),
                    || Svc,
                    serve::ServeOptions::default(),
                );
                let mut conn = client.connect(&fcx, "10.0.0.1:7".parse()?).await?;
                conn.write_all(&fcx, b"bye\n").await?;
                evidence
                    .wait(&fcx, 0, 1, ms(100), |e| {
                        e.is("conn", "close") && e.str("end") == Some("cancelled")
                    })
                    .await?;
                assert!(
                    evidence
                        .checked_all()
                        .unwrap()
                        .iter()
                        .any(|e| e.is("conn", "close") && e.str("end") == Some("cancelled"))
                );
                fcx.cancel();
                Ok(())
            },
        ));
        let _ = tx.send(r.map_err(|e| e.to_string()));
    });
    rx.recv_timeout(Duration::from_secs(20))
        .expect("lab finishes")
        .expect("the world survives connection cancellation");
}

struct SpawnWork(Arc<std::sync::atomic::AtomicBool>);
impl Pending for SpawnWork {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        let stopped = self.0.clone();
        driver.fcx().unwrap().spawn(move |fcx| async move {
            fcx.cancelled().await;
            stopped.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        Poll::Ready(None)
    }
}

struct SpawningSvc(Arc<std::sync::atomic::AtomicBool>);
service_fixture! {
    SpawningSvc => (Lines, (), std::convert::Infallible);

    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }

    on_item(self, _: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        driver.defer(SpawnWork(self.0.clone()));
        Ok(Flow::Close)
    }
}

#[test]
fn finishing_a_connection_cancels_and_joins_its_spawned_work() {
    fictionet::block_on(fictionet::lab(
        RunOptions::new(fictionet::Seed::from_u64(2)),
        |fcx| async move {
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
            let info = fictionet::events::ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
            let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            serve::connection(
                &fcx,
                conn,
                info,
                &mut SpawningSvc(stopped.clone()),
                &(),
                &serve::ServeOptions::default(),
            )
            .await?;
            assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
            assert!(!fcx.is_cancelled());
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

struct BackgroundFailure(bool);
impl Pending for BackgroundFailure {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        if !self.0 {
            driver
                .fcx()
                .unwrap()
                .spawn(|_| async { Err(fictionet::Error::msg("boom")) });
            self.0 = true;
        }
        Poll::Pending
    }
}

#[derive(Default)]
struct TerminalSvc {
    background: bool,
    fail: bool,
    ended: Vec<serve::Ended>,
}
service_fixture! {
    TerminalSvc => (Lines, (), std::io::Error);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_open(self; _, driver) -> Flow {
        if self.fail {
            return Err(std::io::Error::other("service failed first"));
        }
        if self.background {
            driver.defer(BackgroundFailure(false));
        }
        Ok(Flow::Continue)
    }
    on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
        panic!("the terminal connection sends no items")
    }
    on_end(self, end: serve::Ended; _, driver) -> () {
        self.ended.push(end);
        if self.fail && self.background {
            driver.defer(BackgroundFailure(false));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Shutdown {
    Ready(Result<(), ConnError>),
    Pending,
    PendingUntilCancelled,
}

struct TerminalConn {
    shutdown: Shutdown,
    polled: Arc<std::sync::Mutex<Option<fictionet::Cx>>>,
}
impl Connection for TerminalConn {
    fn poll_read(
        &mut self,
        _: &fictionet::Cx,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(Ok(0))
    }

    fn poll_write(
        &mut self,
        _: &fictionet::Cx,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        panic!("these services write no reply")
    }

    fn poll_shutdown(
        &mut self,
        fcx: &fictionet::Cx,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), ConnError>> {
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

#[test]
fn background_error_before_cancel() {
    background_failure(false);
}

#[test]
fn service_error_stays_primary_when_background_work_fails() {
    background_failure(true);
}

fn background_failure(fail: bool) {
    let evidence = std::sync::Arc::new(fictionet::events::Memory::default());
    fictionet::block_on(fictionet::lab(
        RunOptions::new(fictionet::Seed::from_u64(3)).observer(evidence.clone()),
        |fcx| async move {
            let mut service = TerminalSvc {
                background: true,
                fail,
                ..TerminalSvc::default()
            };
            let info = fictionet::events::ConnInfo::new(
                42,
                "10.0.0.1:7".parse()?,
                "10.0.0.2:1234".parse()?,
            );
            let result = serve::connection(
                &fcx,
                TerminalConn {
                    shutdown: Shutdown::Ready(Ok(())),
                    polled: Arc::default(),
                },
                info,
                &mut service,
                &(),
                &serve::ServeOptions::default(),
            )
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("the background failure must reach the caller"),
            };
            if fail {
                assert!(matches!(error, serve::ServeError::Service(_)));
                assert!(
                    fictionet::ErrorChain(&error)
                        .to_string()
                        .contains("service failed first")
                );
                assert_eq!(service.ended, [serve::Ended::Closed]);
            } else {
                assert!(matches!(error, serve::ServeError::Pending(_)), "{error:?}");
                assert!(fictionet::ErrorChain(&error).to_string().contains("boom"));
                assert_eq!(service.ended, [serve::Ended::Cancelled]);
            }
            let errors = evidence.checked_of("conn", "error").unwrap();
            assert_eq!(errors.len(), if fail { 2 } else { 1 });
            if fail {
                assert_eq!(errors[0].str("kind"), Some("service"));
            }
            let task = errors.last().unwrap();
            assert_eq!(task.str("kind"), Some("task"));
            assert_eq!(task.str("error"), Some("boom"));
            assert_eq!(task.conn.id, Some(42));
            let closes = evidence.checked_of("conn", "close").unwrap();
            assert_eq!(closes.len(), 1);
            assert!(closes[0].seq < task.seq, "the region ends after the run");
            assert!(!fcx.is_cancelled());
            Ok(())
        },
    ))
    .unwrap();
}

fn shutdown_outcome(shutdown: Shutdown, cancel: bool, fail: bool, secondary: Option<&'static str>) {
    use std::future::{Future, poll_fn};
    let evidence = std::sync::Arc::new(fictionet::events::Memory::default());
    fictionet::block_on(fictionet::lab(
        RunOptions::new(fictionet::Seed::from_u64(4)).observer(evidence.clone()),
        |fcx| async move {
            let polled = Arc::new(std::sync::Mutex::new(None));
            let mut service = TerminalSvc {
                fail,
                ..TerminalSvc::default()
            };
            let opts = serve::ServeOptions::default().connection_events(true);
            let started = fcx.now();
            let result = {
                let mut served = std::pin::pin!(serve::connection(
                    &fcx,
                    TerminalConn {
                        shutdown,
                        polled: polled.clone(),
                    },
                    fictionet::events::ConnInfo::default(),
                    &mut service,
                    &(),
                    &opts,
                ));
                poll_fn(|cx| {
                    let result = served.as_mut().poll(cx);
                    if result.is_pending() && cancel {
                        // Cancel only after shutdown has actually waited.
                        polled.lock().unwrap().take().unwrap().cancel();
                    }
                    result
                })
                .await
            };
            let end = if fail {
                serve::Ended::Closed
            } else {
                serve::Ended::Eof
            };
            if fail {
                assert!(matches!(result, Err(serve::ServeError::Service(_))));
            } else if cancel {
                assert!(matches!(result, Err(serve::ServeError::Cancelled)));
            } else {
                assert!(matches!(result, Ok(serve::Served::Closed(e)) if e == end));
            }
            if secondary == Some("timed_out") && matches!(shutdown, Shutdown::Pending) {
                assert_eq!(fcx.now(), started + Duration::from_secs(5));
            }
            assert_eq!(
                service.ended,
                [end],
                "on_end runs once with the primary cause"
            );
            let closes = evidence.checked_of("conn", "close").unwrap();
            assert_eq!(closes.len(), 1);
            assert_eq!(closes[0].str("end"), Some(end.as_str()));
            assert_eq!(closes[0].str("shutdown"), secondary);
            assert_eq!(
                evidence.checked_of("conn", "error").unwrap().len(),
                usize::from(fail)
            );
            assert!(!fcx.is_cancelled());
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn shutdown_cancelled_while_pending() {
    shutdown_outcome(Shutdown::Pending, true, false, Some("cancelled"));
}

#[test]
fn shutdown_returns_cancelled() {
    shutdown_outcome(
        Shutdown::PendingUntilCancelled,
        true,
        false,
        Some("cancelled"),
    );
}

#[test]
fn shutdown_timeout_visible() {
    shutdown_outcome(Shutdown::Pending, false, false, Some("timed_out"));
}

#[test]
fn shutdown_transport_error_visible() {
    for (error, name) in [
        (ConnError::Reset, "reset"),
        (ConnError::Closed, "closed"),
        (ConnError::TimedOut, "timed_out"),
        (ConnError::Broken, "broken"),
    ] {
        shutdown_outcome(Shutdown::Ready(Err(error)), false, false, Some(name));
    }
}

#[test]
fn service_error_stays_primary_when_shutdown_is_cancelled() {
    shutdown_outcome(Shutdown::Pending, true, true, Some("cancelled"));
}

#[test]
fn successful_shutdown_has_no_secondary_failure() {
    shutdown_outcome(Shutdown::Ready(Ok(())), false, false, None);
}
