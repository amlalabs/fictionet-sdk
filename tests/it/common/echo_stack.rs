use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::codec::LineError;
use fictionet::stdlib::services::stack::{Job, Tunnel};

use super::line_stack::{DatagramApp, LineApp, LineOut, Lined, Sends};

/// Makes what a handover hands the rest of the stream to.
pub(crate) type Then = Arc<dyn Fn() -> Tunnel + Send + Sync>;

/// Says hello, echoes each line, closes on `quit`, hands over on
/// `handoff` when it has something to hand over to, and on `later`
/// answers through work, in order with the lines around it.
#[derive(Clone, Default)]
pub(crate) struct Echo {
    pub(crate) then: Option<Then>,
}

impl Echo {
    /// An echo as a stack.
    pub(crate) fn stack() -> Lined<Echo> {
        Lined::new(Echo::default())
    }
}

impl LineApp for Echo {
    type Timer = ();
    type Work = Later;
    type Done = Vec<u8>;
    type Next = Tunnel;
    type Error = Infallible;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.write(b"hello\n");
        Ok(())
    }

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        let Ok(line) = line else {
            out.write(b"too long\n");
            return Ok(());
        };
        match line.as_slice() {
            b"quit" => {
                out.write(b"bye\n");
                out.close();
            }
            b"handoff" => {
                if let Some(then) = &self.then {
                    out.hand_over(then());
                }
            }
            b"later" => out.start_in_order(Later { polled: false }),
            _ => {
                out.write(&line);
                out.write(b"\n");
            }
        }
        Ok(())
    }

    fn done(&mut self, done: Vec<u8>, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.write(&done);
        Ok(())
    }

    fn ended(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.write(b"eof\n");
        Ok(())
    }
}

/// Work that is not ready the first time it is polled, and then brings
/// back `later`.
pub(crate) struct Later {
    polled: bool,
}

impl Job for Later {
    type Done = Vec<u8>;

    fn poll(&mut self, _: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        if !self.polled {
            // Not ready the first time: the runner waits for the waker.
            self.polled = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(b"later\n".to_vec())
    }
}

/// Echoes each line of a datagram back to its sender.
pub(crate) struct EchoDatagrams;

impl DatagramApp for EchoDatagrams {
    type Timer = ();

    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        from: SocketAddr,
        sends: &mut Sends<'_, ()>,
    ) {
        let mut answer = line.unwrap_or_default();
        answer.push(b'\n');
        sends.send_to(from, answer);
    }
}

/// Sends `tick` on a timer, three times, then closes.
#[derive(Default)]
pub(crate) struct Ticker {
    pub(crate) ticks: u32,
}

impl LineApp for Ticker {
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Next = Infallible;
    type Error = Infallible;

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.set_timer((), Duration::from_millis(30));
        Ok(())
    }

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        Ok(())
    }

    fn timer(&mut self, _: (), out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        self.ticks += 1;
        out.write(b"tick\n");
        if self.ticks == 3 {
            out.close();
        } else {
            out.set_timer((), Duration::from_millis(30));
        }
        Ok(())
    }
}
