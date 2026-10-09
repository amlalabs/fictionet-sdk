use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::stdlib::serve::{self, Driver, Flow, Pending, PendingDriver, Service};
use fictionet::stdlib::tcp;
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
impl Service for Svc {
    type Decoder = Lines;
    type State = ();
    type Error = std::convert::Infallible;
    fn decoder(&self) -> Lines {
        Lines::new(64, Ending::LfOrCrlf)
    }
    fn on_item(
        &mut self,
        _line: Result<Vec<u8>, LineError>,
        _: &(),
        _driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Close)
    }
    fn on_end(
        &mut self,
        _end: serve::Ended,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<(), Self::Error> {
        // A goodbye written by deferred work: Ending, with ordered work.
        driver.defer(Forever(true));
        Ok(())
    }
}

#[test]
fn cancelling_deferred_end_work_keeps_the_world_running() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
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
                fcx.sleep(ms(100)).await?;
                assert!(
                    fcx.events()
                        .all()
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
