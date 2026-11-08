use fictionet::time::Instant;

/// A layer's armed timers, by name. Arming a name again moves it. Of two
/// timers due at the same moment, the one armed first comes first, so ties
/// break the same way in every run.
///
/// A layer keeps its timers in one of these and answers
/// [`Layer::deadline`](super::Layer::deadline) with [`next`](Self::next).
/// The timers go when the layer goes. Eight inline slots bound engine
/// bookkeeping without allocating. Timer names must be fixed protocol
/// identifiers, not payload containers. Arming a ninth distinct name panics;
/// protocols with more timers should store deadlines with their bounded state.
#[derive(Clone, Debug)]
pub struct Timers<T> {
    armed: [Option<(Instant, T)>; 8],
    len: usize,
}

impl<T> Default for Timers<T> {
    fn default() -> Self {
        Timers {
            armed: std::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl<T: Clone + Eq> Timers<T> {
    /// No timers.
    pub fn new() -> Timers<T> {
        Timers::default()
    }

    /// Arms `timer` to go off at `at`, replacing it if it is armed.
    pub fn set(&mut self, timer: T, at: Instant) {
        self.cancel(&timer);
        assert!(
            self.len < self.armed.len(),
            "too many timer names in one layer"
        );
        self.armed[self.len] = Some((at, timer));
        self.len += 1;
    }

    /// Disarms `timer`. Returns whether it was armed.
    pub fn cancel(&mut self, timer: &T) -> bool {
        let Some(index) = self.armed[..self.len]
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|(_, t)| t == timer))
        else {
            return false;
        };
        self.armed[index..self.len].rotate_left(1);
        self.len -= 1;
        self.armed[self.len] = None;
        true
    }

    /// When `timer` goes off, if it is armed.
    pub fn get(&self, timer: &T) -> Option<Instant> {
        self.armed[..self.len]
            .iter()
            .flatten()
            .find(|(_, t)| t == timer)
            .map(|(at, _)| *at)
    }

    /// The timer due first, and when.
    pub fn next(&self) -> Option<(Instant, T)> {
        self.armed[..self.len]
            .iter()
            .flatten()
            .min_by_key(|(at, _)| *at)
            .map(|(at, t)| (*at, t.clone()))
    }

    /// Disarms `timer` if it is due at `now`. Returns whether it was: a
    /// layer's [`on_timer`](super::Layer::on_timer) starts with this.
    pub fn fire(&mut self, timer: &T, now: Instant) -> bool {
        match self.get(timer) {
            Some(at) if at <= now => self.cancel(timer),
            _ => false,
        }
    }

    /// Disarms every timer `keep` says no to.
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut at = 0;
        while at < self.len {
            if keep(&self.armed[at].as_ref().unwrap().1) {
                at += 1;
            } else {
                self.armed[at..self.len].rotate_left(1);
                self.len -= 1;
                self.armed[self.len] = None;
            }
        }
    }

    /// How many are armed.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether none are armed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
