use std::convert::Infallible;
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::stdlib::services::serve::{Ended, Flow, Pending, PendingDriver, Upgrade};

/// Echoes each line, closes on `quit`, hands over on `handoff`, and on
/// `later` answers through deferred work.
pub(crate) struct Echo;

service_fixture! {
    Echo => (Lines, (), Infallible);

    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }

    on_open(self; _, driver) -> Flow {
        driver.reply().extend_from_slice(b"hello\n");
        Ok(Flow::Continue)
    }

    on_item(self, line: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        let Ok(line) = line else {
            driver.reply().extend_from_slice(b"too long\n");
            return Ok(Flow::Continue);
        };
        driver.emit("echo", "line", |event| event
                .summary(String::from_utf8_lossy(&line))
                .field("bytes", line.len() as u64),
        );
        match line.as_slice() {
            b"quit" => {
                driver.reply().extend_from_slice(b"bye\n");
                Ok(Flow::Close)
            }
            b"handoff" => Ok(Flow::Upgrade(Upgrade::Handoff)),
            b"later" => {
                driver.defer(Later { step: 0 });
                Ok(Flow::Continue)
            }
            _ => {
                driver.reply().extend_from_slice(&line);
                driver.reply().push(b'\n');
                Ok(Flow::Continue)
            }
        }
    }

    on_end(self, end: Ended; _, driver) -> () {
        if end == Ended::Eof {
            driver.reply().extend_from_slice(b"eof\n");
        }
        Ok(())
    }
}

/// Deferred work: waits a little, then sends two chunks.
struct Later {
    step: u8,
}

impl Pending for Later {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
        if self.step == 0 {
            // Not ready the first time: the driver waits for the waker.
            self.step = 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.step += 1;
        match self.step {
            2 => Poll::Ready(Some(Ok(b"la".to_vec()))),
            3 => {
                driver.emit("echo", "later", |event| {
                    event.field("written", driver.written())
                });
                Poll::Ready(Some(Ok(b"ter\n".to_vec())))
            }
            _ => Poll::Ready(None),
        }
    }
}

/// Sends `tick` on a timer, three times, then closes.
pub(crate) struct Ticker {
    pub(crate) ticks: u32,
}

service_fixture! {
    Ticker => (Lines, (), Infallible);

    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }

    on_open(self; _, driver) -> Flow {
        driver.set_timer((), Duration::from_millis(30));
        Ok(Flow::Continue)
    }

    on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
        Ok(Flow::Continue)
    }

    on_timer(self, _: (); _, driver) -> Flow {
        self.ticks += 1;
        driver.reply().extend_from_slice(b"tick\n");
        if self.ticks == 3 {
            return Ok(Flow::Close);
        }
        driver.set_timer((), Duration::from_millis(30));
        Ok(Flow::Continue)
    }
}
