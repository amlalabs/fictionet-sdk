//! [`block_on`]: the executor for a world that needs no other.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// Runs `future` on the current thread, blocking until it finishes, and
/// returns its output.
///
/// Use it for a world that needs no other executor. The thread sleeps while
/// `future` waits, and wakes when the helper threads behind
/// [`listen`](crate::listen) and the timers wake it. A world on tokio awaits
/// [`run`](crate::run) inside the tokio runtime instead.
///
/// In a browser (wasm32-unknown-unknown) a thread cannot sleep, and only
/// the run's own timers can wake the future. There `block_on` fires the
/// timers itself and spins while it waits for the next one, which holds
/// the page's thread for as long as the world runs. It suits a test, a Web
/// Worker or Node.js. A page hands [`run`](crate::run) to its event loop
/// instead, for example with `wasm_bindgen_futures::spawn_local`, and the
/// timers fire from `setTimeout`.
///
/// `block_on` is not a tokio runtime. Anything that needs one, such as
/// everything behind the `tokio` feature or a tokio-based database client,
/// fails under `block_on`. Such a world runs on tokio.
///
/// ```no_run
/// # use fictionet::{Attachments, Cx, Result};
/// # async fn world(_fcx: Cx, _attachments: Attachments) -> Result { Ok(()) }
/// fn main() -> fictionet::Result {
///     let (attacher, attachments) = fictionet::attachments();
///     let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
///     let _listening = fictionet::listen(socket, attacher)?;
///     fictionet::block_on(fictionet::run(|fcx| world(fcx, attachments)))
/// }
/// ```
pub fn block_on<F: Future>(future: F) -> F::Output {
    #[cfg(not(target_arch = "wasm32"))]
    return park_on(future);
    #[cfg(target_arch = "wasm32")]
    return spin_on(future);
}

/// Sleeps the thread while `future` waits.
#[cfg(not(target_arch = "wasm32"))]
fn park_on<F: Future>(future: F) -> F::Output {
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

/// Fires the run's timers while `future` waits.
#[cfg(target_arch = "wasm32")]
fn spin_on<F: Future>(future: F) -> F::Output {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Woken(AtomicBool);
    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }
    let woken = Arc::new(Woken(AtomicBool::new(false)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        // Nothing else runs in this thread while it waits, so only a timer
        // coming due can wake the future.
        while !woken.0.swap(false, Ordering::AcqRel) {
            if crate::timer::timers().fire().is_none() && !woken.0.load(Ordering::Acquire) {
                panic!(
                    "block_on: the future waits for something that nothing in this thread can wake"
                );
            }
            std::hint::spin_loop();
        }
    }
}
