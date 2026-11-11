//! Cost bounds for a replay: each step of a trace or a vector session is
//! measured with the counting allocator (alloc.rs beside this file) and
//! held to two bounds stated before it runs.
//!
//! - **Within the charge**: the most bytes live at any moment of the step,
//!   counting everything the replayed part allocated since its session
//!   began, is at most what was charged for it, plus what the step itself
//!   charged to a budget (a block it grew).
//! - **Linear in the input**: the bytes the step asked the allocator for,
//!   each reallocation at its full new size, are at most `per * input +
//!   fixed` for the step's input bytes, with `per` and `fixed` named and
//!   justified where the bound is made. Every byte a step copies into
//!   fresh storage is first asked for, so a step that copies what it
//!   holds on each delivery, which is quadratic over a stream, breaks this
//!   bound as its input grows. An [`amortized`](Costs::amortized) session
//!   holds the bound over its steps together instead, for a holder that
//!   copies each byte a bounded number of times, but not in the step that
//!   brought it.
//!
//! A bound that fails names its session and step and both sides of the
//! inequality. Build what a session replays inside its steps (the table,
//! the connection): the running count of live bytes starts at zero with
//! the session, and only allocations made inside a step are counted.
//!
//! Include beside the allocator, in a test binary:
//!
//! ```ignore
//! #[path = "<to the repository>/verification/resources/alloc.rs"]
//! mod alloc;
//! #[path = "<to the repository>/verification/resources/cost.rs"]
//! mod cost;
//! ```

// Each binary that includes it uses only part of it.
#![allow(dead_code)]

use std::string::String;

use super::alloc::measuring_left;

/// `per * input + fixed` bytes, with `per` a fraction `num / den`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Linear {
    /// The numerator of the bytes allowed per input byte.
    pub num: usize,
    /// Its denominator.
    pub den: usize,
    /// The bytes allowed whatever the input.
    pub fixed: usize,
}

impl Linear {
    /// The bytes allowed for `input` bytes of input.
    pub(crate) fn at(&self, input: usize) -> usize {
        input
            .saturating_mul(self.num)
            .div_ceil(self.den)
            .saturating_add(self.fixed)
    }
}

/// The cost of one session's steps, checked as they run.
pub(crate) struct Costs {
    session: String,
    steps: usize,
    /// Bytes live from the session's allocations, after the last step.
    live: i128,
    /// What [`held_charge`](Self::held_charge) has risen to.
    charge: usize,
    /// The step that came closest to its charge: (peak, allowed).
    closest_charge: (usize, usize),
    /// The step that came closest to its linear bound: (requested, allowed).
    closest_linear: (usize, usize),
    /// Whether the linear bound holds over the session's steps together
    /// ([`amortized`](Self::amortized)) rather than each step's.
    amortized: bool,
    /// Bytes asked for by every step so far.
    total_requested: usize,
    /// What the linear bounds of every step so far allow together.
    total_allowed: usize,
}

/// The step's work, and what it charged to a budget besides.
pub(crate) struct Charged<T> {
    /// What the step returns.
    pub value: T,
    /// Bytes the step itself charged to a budget, such as a block it grew.
    pub charged: usize,
    /// Bytes a reallocation moved into storage the step charged: growing
    /// a container asks the allocator for its old contents again. Allowed
    /// in the linear bound, not in the charge. A container that at least
    /// doubles moves no more than it charged.
    pub moved: usize,
}

impl Costs {
    /// A session named `session` in failure messages, with nothing live.
    pub(crate) fn new(session: impl Into<String>) -> Self {
        Self {
            session: session.into(),
            steps: 0,
            live: 0,
            charge: 0,
            closest_charge: (0, 1),
            closest_linear: (0, 1),
            amortized: false,
            total_requested: 0,
            total_allowed: 0,
        }
    }

    /// A session whose linear bound holds over its steps together: what
    /// they ask for in all is at most what their bounds allow in all. For a holder that copies
    /// each byte a bounded number of times but not in the step it came
    /// in, as a store that joins blocks to free places does. The charge
    /// still holds at every step.
    pub(crate) fn amortized(session: impl Into<String>) -> Self {
        Self {
            amortized: true,
            ..Self::new(session)
        }
    }

    /// The charge of a holder that pays its bound when it opens, raises
    /// the charge when the bound rises, and gives none of it back until
    /// it closes, as the HTTP/2 server holds its HPACK table's: the most
    /// `bound` this session has passed, `bound` included.
    pub(crate) fn held_charge(&mut self, bound: usize) -> usize {
        self.charge = self.charge.max(bound);
        self.charge
    }

    /// Runs one step on `input` bytes, with `charge` paid for what the
    /// session holds, and checks it against `charge` and `linear`.
    pub(crate) fn step<T>(
        &mut self,
        input: usize,
        charge: usize,
        linear: Linear,
        f: impl FnOnce() -> Charged<T>,
    ) -> T {
        let (done, stats, left) = measuring_left(f);
        let step = self.steps;
        self.steps += 1;
        let before = usize::try_from(self.live.max(0)).unwrap_or(usize::MAX);
        let peak = before.saturating_add(stats.peak_live_bytes);
        let allowed = charge.saturating_add(done.charged);
        assert!(
            peak <= allowed,
            "{} step {step}: {peak} bytes live at once, past the {charge} charged \
             and {} the step charged",
            self.session,
            done.charged,
        );
        let bound = linear
            .at(input)
            .saturating_add(done.charged)
            .saturating_add(done.moved);
        self.total_requested = self.total_requested.saturating_add(stats.bytes_requested);
        self.total_allowed = self.total_allowed.saturating_add(bound);
        let (requested, bound) = if self.amortized {
            (self.total_requested, self.total_allowed)
        } else {
            (stats.bytes_requested, bound)
        };
        assert!(
            requested <= bound,
            "{} step {step}: {requested} bytes asked for{} on {input} bytes of input, \
             past {bound} allowed by {linear:?}, {} the step charged and {} it moved",
            self.session,
            if self.amortized { " in all" } else { "" },
            done.charged,
            done.moved,
        );
        self.live += left;
        if peak * self.closest_charge.1 > self.closest_charge.0 * allowed {
            self.closest_charge = (peak, allowed);
        }
        if requested * self.closest_linear.1 > self.closest_linear.0 * bound {
            self.closest_linear = (requested, bound.max(1));
        }
        done.value
    }

    /// The bytes the session's steps have left allocated, as counted from
    /// its start: what it holds now.
    pub(crate) fn live(&self) -> usize {
        usize::try_from(self.live.max(0)).unwrap_or(usize::MAX)
    }

    /// Takes in another session's steps and closest calls, for a summary
    /// over many sessions.
    pub(crate) fn absorb(&mut self, other: &Self) {
        self.steps += other.steps;
        let (p, a) = other.closest_charge;
        if p * self.closest_charge.1 > self.closest_charge.0 * a {
            self.closest_charge = (p, a);
        }
        let (r, b) = other.closest_linear;
        if r * self.closest_linear.1 > self.closest_linear.0 * b {
            self.closest_linear = (r, b);
        }
    }

    /// One line: the steps checked, and the closest each bound came.
    pub(crate) fn summary(&self) -> String {
        std::format!(
            "{} steps within their charge and linear bound; closest: {} of {} bytes \
             charged, {} of {} bytes allowed",
            self.steps,
            self.closest_charge.0,
            self.closest_charge.1,
            self.closest_linear.0,
            self.closest_linear.1,
        )
    }
}
