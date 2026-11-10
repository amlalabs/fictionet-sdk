//! [`block_on`]: the executor for a world that needs no other.

use std::future::Future;
use std::task::{Context, Poll, Waker};

/// Runs `future` on the current thread, blocking until it finishes, and
/// returns its output.
///
/// Use it for a world that needs no other executor. The thread sleeps while
/// `future` waits, and wakes when the helper threads behind
/// [`listen`](crate::listen) and the timers wake it. A world on tokio awaits
/// [`run`](crate::run) inside the tokio runtime instead.
///
/// In a browser (wasm32-unknown-unknown) a thread cannot sleep, and only
/// the run's own timers can wake the future. There `block_on` polls the
/// future over and over, and the run fires each timer as it comes due,
/// which holds the page's thread for as long as the world runs. It suits a test, a Web
/// Worker or Node.js. A page hands [`run`](crate::run) to its event loop
/// instead, for example with `wasm_bindgen_futures::spawn_local`, and the
/// timers fire from `setTimeout`.
///
/// `block_on` is not a tokio runtime. Anything that needs one, such as
/// a tokio-based database client,
/// fails under `block_on`. Such a world runs on tokio.
///
/// The [Running a world](crate#running-a-world) example shows a complete `main`.
/// It uses this executor to run the world.
pub fn block_on<F: Future>(future: F) -> F::Output {
    #[cfg(not(target_arch = "wasm32"))]
    return park_on(future);
    #[cfg(target_arch = "wasm32")]
    return spin_on(future);
}

/// Sleeps the thread while `future` waits.
#[cfg(not(target_arch = "wasm32"))]
fn park_on<F: Future>(future: F) -> F::Output {
    use std::sync::Arc;
    use std::task::Wake;

    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        // A wake that came during the poll leaves a token, so this returns
        // immediately.
        std::thread::park();
    }
}

/// Polls `future` again and again: a run polled with nothing to do fires
/// its own due timers.
#[cfg(target_arch = "wasm32")]
fn spin_on<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        // Nothing else runs in this thread while it waits, and no
        // `setTimeout` can fire, so a timer coming due is only seen by
        // polling again.
        std::hint::spin_loop();
    }
}
