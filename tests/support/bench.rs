//! The benchmarks' worlds: a fixture that stops at checkpoints, and the HTTP
//! cases that the SDK's and the command's benchmarks share.

pub mod http;

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use fictionet::{Cx, block_on, run};
use tokio::sync::oneshot;

pub fn finish(result: fictionet::Result) {
    if let Err(error) = result
        && !error.is::<fictionet::Cancelled>()
    {
        panic!("the world failed: {error}");
    }
}

pub struct Checkpoint(Arc<Mutex<Option<oneshot::Sender<()>>>>);

impl Checkpoint {
    pub async fn wait(&self) {
        let (send, recv) = oneshot::channel();
        *self.0.lock().unwrap() = Some(send);
        recv.await.unwrap();
    }
}

// Keep the world on the benchmark thread so Divan profiles its allocations.
// The first checkpoint ends setup; the second ends the measured work.
// Dropping the fixture runs cleanup outside the measured interval.
pub struct World {
    future: Pin<Box<dyn Future<Output = fictionet::Result> + Send>>,
    checkpoint: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

impl World {
    pub fn new<F, Fut>(work: F) -> Self
    where
        F: FnOnce(Cx, Checkpoint) -> Fut + Send + 'static,
        Fut: Future<Output = fictionet::Result> + Send + 'static,
    {
        let checkpoint = Arc::new(Mutex::new(None));
        let pause = Checkpoint(checkpoint.clone());
        let future = Box::pin(run(fictionet::Seed::random(), move |fcx| work(fcx, pause)));
        let mut world = Self { future, checkpoint };
        world.advance();
        world
    }

    fn resume(&self) {
        if let Some(send) = self.checkpoint.lock().unwrap().take() {
            send.send(()).unwrap();
        }
    }

    fn advance(&mut self) {
        self.resume();
        block_on(poll_fn(|cx| {
            if let Poll::Ready(result) = self.future.as_mut().poll(cx) {
                finish(result);
                panic!("the world ended before its checkpoint");
            }
            if self.checkpoint.lock().unwrap().is_some() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
    }

    pub fn measure(mut self) -> Self {
        self.advance();
        self
    }
}

impl Drop for World {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.resume();
            finish(block_on(self.future.as_mut()));
        }
    }
}
