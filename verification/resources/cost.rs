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
//!   bound as its input grows.
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

use crate::alloc::measuring_left;

/// `per * input + fixed` bytes, with `per` a fraction `num / den`.
#[derive(Clone, Copy, Debug)]
pub struct Linear {
    /// The numerator of the bytes allowed per input byte.
    pub num: usize,
    /// Its denominator.
    pub den: usize,
    /// The bytes allowed whatever the input.
    pub fixed: usize,
}

impl Linear {
    /// The bytes allowed for `input` bytes of input.
    pub fn at(&self, input: usize) -> usize {
        input
            .saturating_mul(self.num)
            .div_ceil(self.den)
            .saturating_add(self.fixed)
    }
}

/// The cost of one session's steps, checked as they run.
pub struct Costs {
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
}

/// The step's work, and what it charged to a budget besides.
pub struct Charged<T> {
    /// What the step returns.
    pub value: T,
    /// Bytes the step itself charged to a budget, such as a block it grew.
    pub charged: usize,
}

impl Costs {
    /// A session named `session` in failure messages, with nothing live.
    pub fn new(session: impl Into<String>) -> Costs {
        Costs {
            session: session.into(),
            steps: 0,
            live: 0,
            charge: 0,
            closest_charge: (0, 1),
            closest_linear: (0, 1),
        }
    }

    /// The charge of a holder that pays its bound when it opens, raises
    /// the charge when the bound rises, and gives none of it back until
    /// it closes, as the HTTP/2 server holds its HPACK table's: the most
    /// `bound` this session has passed, `bound` included.
    pub fn held_charge(&mut self, bound: usize) -> usize {
        self.charge = self.charge.max(bound);
        self.charge
    }

    /// Runs one step on `input` bytes, with `charge` paid for what the
    /// session holds, and checks it against `charge` and `linear`.
    pub fn step<T>(
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
        let bound = linear.at(input).saturating_add(done.charged);
        assert!(
            stats.bytes_requested <= bound,
            "{} step {step}: {} bytes asked for on {input} bytes of input, past \
             {linear:?} and {} the step charged",
            self.session,
            stats.bytes_requested,
            done.charged,
        );
        self.live += left;
        if peak * self.closest_charge.1 > self.closest_charge.0 * allowed {
            self.closest_charge = (peak, allowed);
        }
        if stats.bytes_requested * self.closest_linear.1 > self.closest_linear.0 * bound {
            self.closest_linear = (stats.bytes_requested, bound.max(1));
        }
        done.value
    }

    /// Takes in another session's steps and closest calls, for a summary
    /// over many sessions.
    pub fn absorb(&mut self, other: &Costs) {
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
    pub fn summary(&self) -> String {
        format!(
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
