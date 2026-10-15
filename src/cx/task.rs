use fictionet::sync::Mutex;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Poll, Waker};

use super::{CancelWait, Cancelled, Cx};

/// Why [`Task::join`] has no `Ok` for its task.
#[derive(Clone, Debug)]
pub enum JoinError {
    /// The task returned this error. It is the same error its region
    /// keeps, shared, not a copy: downcast it to the task's own type.
    Failed(crate::Error),
    /// The task did not finish: it ended with a cancel, or the region of
    /// the `Cx` passed to `join` was cancelled with no task result ready,
    /// or the run was dropped, or admission was refused because the task's
    /// region had completed.
    Cancelled,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Failed(_) => f.write_str("the task failed"),
            JoinError::Cancelled => f.write_str("the join stopped"),
        }
    }
}

impl std::error::Error for JoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JoinError::Failed(e) => Some(&**e),
            JoinError::Cancelled => Some(&Cancelled),
        }
    }
}

impl From<Cancelled> for JoinError {
    fn from(_: Cancelled) -> Self {
        JoinError::Cancelled
    }
}

/// A handle to a background task started with [`Cx::spawn`].
///
/// Dropping it detaches the task: the task keeps running, because its
/// [region](Cx#regions) owns it, not the handle. A task stops when it
/// returns, or when its region is cancelled, together with the rest of the
/// region. Keep the handle to wait for the task with [`Task::join`].
pub struct Task {
    pub(super) join: Arc<JoinState>,
}

impl Task {
    /// Waits for the task to end. `Ok(())` if it returned `Ok`.
    ///
    /// If the task failed, this returns [`JoinError::Failed`] with the
    /// task's own error, the same one its region keeps, as [`Cx::spawn`]
    /// says. Each poll checks for a stored task result before checking
    /// `fcx`'s cancellation. Any stored result wins, including `Ok(())`.
    /// A failure is stored before it cancels the region, so a joiner in
    /// that same region still gets the error.
    ///
    /// If no result is ready and `fcx`'s region is cancelled, this returns
    /// [`JoinError::Cancelled`]. It also returns `Cancelled` if the task
    /// ended with a cancel, was dropped with the run, or was refused
    /// because its region had completed.
    pub async fn join(self, fcx: &Cx) -> Result<(), JoinError> {
        let mut wait = CancelWait::default();
        poll_fn(|cx| {
            let mut state = self.join.state.lock();
            if let Some(result) = state.result.take() {
                return Poll::Ready(result);
            }
            if fcx.is_cancelled() {
                return Poll::Ready(Err(JoinError::Cancelled));
            }
            match &state.waker {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => state.waker = Some(cx.waker().clone()),
            }
            drop(state);
            if fcx.register_cancel(cx.waker(), &mut wait) {
                return Poll::Ready(Err(JoinError::Cancelled));
            }
            Poll::Pending
        })
        .await
    }
}

/// What a [`Task`] returned, for [`Task::join`].
#[derive(Default)]
pub(crate) struct JoinState {
    state: Mutex<JoinInner>,
}

#[derive(Default)]
struct JoinInner {
    result: Option<Result<(), JoinError>>,
    waker: Option<Waker>,
}

impl JoinState {
    pub(crate) fn finish(&self, result: Result<(), JoinError>) {
        let waker = {
            let mut state = self.state.lock();
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}
