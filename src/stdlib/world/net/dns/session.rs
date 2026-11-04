//! The session a world's DNS programs answer for, and state that belongs
//! to one session.

use std::sync::Arc;

use fictionet::stdlib::services::dns::{Generation, Session, WallClock};
use fictionet::sync::Mutex;

/// The session a world's DNS programs answer for: a generation that only
/// grows, and the date its signatures are checked against.
///
/// A world advances it when its session changes, such as when a run
/// switches from live pages to a capture. Every program given the
/// namespace moves to the new session before its next input: each
/// engine abandons what it was waiting for, a resolver empties its cache
/// and starts the queries still waiting again, an authority drops what
/// its lookups filed, and nothing that completes for the old session can
/// change the new one. Guests keep their own caches until the TTLs run
/// out; a session change cannot reach them.
#[derive(Clone)]
pub struct Namespace {
    session: Arc<Mutex<Session>>,
}

impl Namespace {
    /// A namespace in generation 0, whose dates come from `clock`.
    pub fn new(clock: WallClock) -> Namespace {
        Namespace {
            session: Arc::new(Mutex::new(Session {
                generation: Generation(0),
                clock,
            })),
        }
    }

    /// Starts a new session whose dates come from `clock`, and returns it.
    pub fn advance(&self, clock: WallClock) -> Session {
        let mut session = self.session.lock();
        *session = Session {
            generation: Generation(session.generation.0 + 1),
            clock,
        };
        *session
    }

    /// The current session.
    pub fn current(&self) -> Session {
        *self.session.lock()
    }
}

/// State that belongs to one session, such as what the servers' replies
/// named in it: it starts afresh when a later session uses it, so nothing
/// one session learned reaches the next.
pub struct PerSession<T> {
    state: Mutex<(Generation, T)>,
}

impl<T: Default> PerSession<T> {
    /// Fresh state for generation 0.
    pub fn new() -> PerSession<T> {
        PerSession {
            state: Mutex::new((Generation(0), T::default())),
        }
    }

    /// `f` with the state of session `generation`, made afresh first when
    /// the state belongs to an earlier session.
    ///
    /// A caller still working for a session that has since ended gets
    /// fresh state of its own, which is dropped afterwards, so nothing it
    /// does reaches the later session's state.
    pub fn with<R>(&self, generation: Generation, f: impl FnOnce(&mut T) -> R) -> R {
        let mut state = self.state.lock();
        if generation < state.0 {
            return f(&mut T::default());
        }
        if generation > state.0 {
            *state = (generation, T::default());
        }
        f(&mut state.1)
    }
}

impl<T: Default> Default for PerSession<T> {
    fn default() -> PerSession<T> {
        PerSession::new()
    }
}
