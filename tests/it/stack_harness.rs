//! A line stack in the layer harness with no runtime, and over a live
//! connection, where the runner's idle clock waits for the stack's work.

use crate::common::echo_stack::{Echo, Ticker};
use crate::common::line_stack::{LineApp, LineOut, Lined};

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::codec::{Fail, Frames, LineError, Wire};
use fictionet::stdlib::layer::{
    Admit, Budget, Chain, Decoded, Env, Framed, Framing, Harness, Layer, MessageCommand,
    MessageEvent, Owned, Top,
};
use fictionet::stdlib::network::{ConnInfo, ip, tcp};
use fictionet::stdlib::protocols::modbus::{self, Exception, Frame};
use fictionet::stdlib::services::stack::{self, Job, Polling, StreamEnd, StreamLimits};
use fictionet::{Cx, Seed};

#[test]
fn the_harness_runs_a_stack_with_no_runtime() {
    let mut h = Harness::new(Seed::from_u64(0), Echo::stack()).with_worker(Polling::new());
    h.settle().unwrap();
    assert_eq!(h.take_output(), b"hello\n");
    h.push(b"one\ntw").unwrap();
    assert_eq!(h.take_output(), b"one\n");
    h.push(b"o\n").unwrap();
    assert_eq!(h.take_output(), b"two\n");
    // A line past the limit is one error item, and the stack goes on.
    h.push(&[b'x'; 100]).unwrap();
    assert_eq!(h.take_output(), b"too long\n");
    h.push(b"\nthree\n").unwrap();
    assert_eq!(h.take_output(), b"three\n");
    h.push(b"quit\n").unwrap();
    assert_eq!(h.take_output(), b"bye\n");
    assert!(h.ended(), "the stack closed its direction");
    h.push(b"more\n").unwrap();
    assert!(h.input_closed(), "a closed stack reads nothing more");
    assert!(h.take_output().is_empty());
}

#[test]
fn the_harness_moves_its_clock_and_ticks() {
    let mut h = Harness::new(Seed::from_u64(0), Lined::new(Ticker::default()));
    h.settle().unwrap();
    assert!(h.layer().timer(&()).is_some());
    h.advance(Duration::from_millis(10)).unwrap();
    assert_eq!(h.take_output(), b"");
    h.advance(Duration::from_millis(25)).unwrap();
    assert_eq!(h.take_output(), b"tick\n");
    h.advance(Duration::from_millis(30)).unwrap();
    assert_eq!(h.take_output(), b"tick\n");
    h.advance(Duration::from_millis(30)).unwrap();
    assert_eq!(h.take_output(), b"tick\n");
    assert!(h.ended());
}

#[test]
fn a_half_close_ends_with_the_last_reply() {
    let mut h = Harness::new(Seed::from_u64(0), Echo::stack()).with_worker(Polling::new());
    h.push(b"a\nb").unwrap();
    assert_eq!(h.take_output(), b"hello\na\n");
    // The unterminated line is an error item at the end, then the end.
    h.end().unwrap();
    assert_eq!(h.take_output(), b"too long\neof\n");
    assert!(h.ended());
}

/// Answers nothing until framing fails, then answers that with an
/// exception and keeps the failure.
#[derive(Default)]
struct Strict {
    failed: Option<Fail<modbus::Error>>,
    answer: Option<Owned<Frame>>,
    over: bool,
    end_sent: bool,
}

type ModbusPort = Framing<Frames<Frame>, Frame>;

/// The exception Strict answers a framing failure with.
fn refusal() -> Frame {
    Frame {
        transaction: 0,
        unit: 0,
        pdu: Exception::IllegalFunction.to_pdu(0),
    }
}

impl Layer for Strict {
    type Lower = ModbusPort;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: MessageEvent<Decoded<Frames<Frame>>>,
    ) -> Result<Admit<MessageEvent<Decoded<Frames<Frame>>>>, Infallible> {
        match event {
            MessageEvent::Message(Ok(_)) => {}
            MessageEvent::Message(Err(fail)) => {
                self.failed = Some(fail);
                let charge = env.budget().charge(64).expect("an unlimited budget");
                self.answer = Some(Owned::new(refusal(), charge));
            }
            MessageEvent::Ended => self.over = true,
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

    fn take_command(&mut self) -> Option<MessageCommand<Owned<Frame>>> {
        if let Some(answer) = self.answer.take() {
            return Some(MessageCommand::Send(answer));
        }
        if self.over && !self.end_sent {
            self.end_sent = true;
            return Some(MessageCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

#[test]
fn a_framing_failure_is_handed_to_the_stack_which_answers_it() {
    let stack: Chain<Framed<Frames<Frame>, Frame>, Strict> =
        Chain::new(Framed::new(Frames::<Frame>::new()), Strict::default());
    let mut h = Harness::new(Seed::from_u64(0), stack);
    // Protocol id 7: not Modbus.
    let bad = [0, 1, 0, 7, 0, 6, 1, 3, 0, 0, 0, 1];
    h.push(&bad).unwrap();
    assert_eq!(h.output(), Wire::to_bytes(&refusal()).unwrap());
    assert!(
        matches!(h.layer().upper().failed, Some(Fail::Protocol(_))),
        "the stack heard the failure"
    );
    assert!(h.ended(), "nothing can be read after a framing failure");
}

/// Work that ends once its gate opens.
struct Gated(Arc<Mutex<Gate>>);

#[derive(Default)]
struct Gate {
    open: bool,
    waker: Option<Waker>,
}

impl Job for Gated {
    type Done = ();

    fn poll(&mut self, _: Option<&Cx>, cx: &mut Context<'_>) -> Poll<()> {
        let mut gate = self.0.lock().unwrap();
        if gate.open {
            return Poll::Ready(());
        }
        gate.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Starts gated work for each line, and reads on once it is done.
struct Deferring(Arc<Mutex<Gate>>);

impl LineApp for Deferring {
    type Timer = ();
    type Work = Gated;
    type Done = ();
    type Next = Infallible;
    type Error = Infallible;

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        out.start_in_order(Gated(self.0.clone()));
        Ok(())
    }
}

/// The idle clock counts only while the runner waits for the client.
/// Running work suspends it: once the work is done, the client has the
/// whole idle time to speak before its input is ended as idle.
#[test]
fn the_idle_clock_restarts_after_work() {
    let idle = Duration::from_secs(10);
    let server: SocketAddr = (Ipv4Addr::new(10, 9, 0, 1), 7).into();
    fictionet_test_support::world::world(Duration::from_secs(60), move |fcx| async move {
        let (a, b) = fictionet::pair();
        let (at, _au, _ai, _ao) = ip::split_protocols(&fcx, a);
        let (bt, _bu, _bi, _bo) = ip::split_protocols(&fcx, b);
        let server_tcp = tcp::endpoint(&fcx, at, server.ip());
        let client = tcp::endpoint(&fcx, bt, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)));
        let mut listener = server_tcp.listen(server.port())?;
        let gate = Arc::new(Mutex::new(Gate::default()));
        let ended = Arc::new(Mutex::new(None));
        let (stack_gate, slot) = (gate.clone(), ended.clone());
        fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
            let limits = StreamLimits {
                idle: Some(idle),
                ..StreamLimits::default()
            };
            let stack = Lined::new(Deferring(stack_gate));
            let budget = Budget::unlimited();
            let end = stack::stream(&fcx, conn, &info, stack, budget, limits, |_| {}).await;
            *slot.lock().unwrap() = Some((end.map_err(|e| format!("{e:?}")), fcx.now()));
            Ok(())
        });
        let mut conn = client.connect(&fcx, server).await?;
        conn.write_all(&fcx, b"work\n").await?;
        // The work outlasts the idle limit; the runner waits for it, not
        // the client.
        fcx.sleep(idle + idle).await?;
        assert!(
            ended.lock().unwrap().is_none(),
            "running work is not a silent client"
        );
        let done_at = fcx.now();
        let waker = {
            let mut gate = gate.lock().unwrap();
            gate.open = true;
            gate.waker.take()
        };
        waker.expect("the runner polled the work").wake();
        assert_eq!(conn.read(&fcx, &mut [0; 8]).await?, 0);
        let (end, at) = ended.lock().unwrap().take().expect("the run ended");
        assert_eq!(end, Ok(StreamEnd::Idle));
        assert_eq!(
            at.since_start() - done_at.since_start(),
            idle,
            "the client had the whole idle time once the work ended"
        );
        Ok(())
    });
}
