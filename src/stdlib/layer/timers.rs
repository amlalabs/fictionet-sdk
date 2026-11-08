use fictionet::time::Instant;

/// A layer's armed timers, by name. Arming a name again moves it. Of two
/// timers due at the same moment, the one armed first comes first, so ties
/// break the same way in every run.
///
/// A layer keeps its timers in one of these and answers
/// [`Layer::deadline`](super::Layer::deadline) with [`next`](Self::next).
/// The timers go when the layer goes.
#[derive(Clone, Debug)]
pub struct Timers<T> {
    armed: Vec<(Instant, u64, T)>,
    armings: u64,
}

impl<T> Default for Timers<T> {
    fn default() -> Self {
        Timers {
            armed: Vec::new(),
            armings: 0,
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
        self.armings += 1;
        self.armed.push((at, self.armings, timer));
    }

    /// Disarms `timer`. Returns whether it was armed.
    pub fn cancel(&mut self, timer: &T) -> bool {
        let before = self.armed.len();
        self.armed.retain(|(_, _, t)| t != timer);
        self.armed.len() != before
    }

    /// When `timer` goes off, if it is armed.
    pub fn get(&self, timer: &T) -> Option<Instant> {
        self.armed
            .iter()
            .find(|(_, _, t)| t == timer)
            .map(|(at, _, _)| *at)
    }

    /// The timer due first, and when.
    pub fn next(&self) -> Option<(Instant, T)> {
        self.armed
            .iter()
            .min_by_key(|(at, order, _)| (*at, *order))
            .map(|(at, _, t)| (*at, t.clone()))
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
        self.armed.retain(|(_, _, t)| keep(t));
    }

    /// How many are armed.
    pub fn len(&self) -> usize {
        self.armed.len()
    }

    /// Whether none are armed.
    pub fn is_empty(&self) -> bool {
        self.armed.is_empty()
    }
}
