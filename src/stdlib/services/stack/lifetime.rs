use fictionet::time::Instant;

use super::StreamLimits;

/// When a stream gives up on its peer, and when it is done: the policy
/// [`Session`](super::Session) and the stream adapter share. Each adapter
/// moves the bytes and reports what happened; this decides.
///
/// A stream is idle only while no byte moves in either direction and
/// nothing is outstanding: input is open and none is held, no output is
/// held, no work runs, and the stream does not wait for memory. The idle
/// limit counts from the first settle that finds it so, and any byte read
/// or written starts it again. The write limit counts while output is
/// held, from the last byte that went out, whether or not the stream also
/// waits for memory.
pub(super) struct Lifetime {
    limits: StreamLimits,
    /// When the idle limit started counting, while the stream waits.
    idle_from: Option<Instant>,
    /// When the last byte went out, while output is held.
    stalled_since: Option<Instant>,
    input_over: bool,
    output_over: bool,
    idled: bool,
}

/// What a stream still has under way, as its adapter sees it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Outstanding {
    /// Output the transport has not taken.
    pub(super) output: bool,
    /// Input the application has not taken.
    pub(super) input: bool,
    /// Work the application handed over that has not finished.
    pub(super) work: bool,
    /// The stream waits for memory: the budget refused a charge in the
    /// round that settles, and the release that makes room for it wakes
    /// the stream. Time spent so is not spent waiting for the peer.
    pub(super) memory: bool,
}

/// A limit that ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Expiry {
    /// The peer sent nothing for the idle limit while the stream waited:
    /// the application hears its input end.
    Idle,
    /// No byte went out for the write limit: the stream gives up on the
    /// peer.
    Stalled,
}

impl Lifetime {
    pub(super) fn new(limits: StreamLimits) -> Lifetime {
        Lifetime {
            limits,
            idle_from: None,
            stalled_since: None,
            input_over: false,
            output_over: false,
            idled: false,
        }
    }

    /// Input came from the peer, or the application took it: the idle limit counts again from the next
    /// [`settle`](Self::settle). The write limit keeps counting, since a
    /// peer that sends is not one that reads.
    pub(super) fn took_input(&mut self) {
        self.idle_from = None;
    }

    /// Bytes went out: the idle limit and the write limit count again from
    /// the next [`settle`](Self::settle). A stream that sends is not
    /// idle, even when its peer says nothing.
    pub(super) fn wrote(&mut self) {
        self.stalled_since = None;
        self.idle_from = None;
    }

    /// The adapter stopped for its own work: that time is not spent
    /// waiting for the peer, so the idle limit counts again from the next
    /// [`settle`](Self::settle).
    pub(super) fn interrupt(&mut self) {
        self.idle_from = None;
    }

    /// The input ended, was reset, or the application refused it as closed.
    pub(super) fn end_input(&mut self) {
        self.input_over = true;
    }

    /// The application's end of its direction went out.
    pub(super) fn end_output(&mut self) {
        self.output_over = true;
    }

    pub(super) fn input_over(&self) -> bool {
        self.input_over
    }

    pub(super) fn output_over(&self) -> bool {
        self.output_over
    }

    /// Whether the idle limit ended the input.
    pub(super) fn idled(&self) -> bool {
        self.idled
    }

    /// Starts or stops each limit's clock for what is `outstanding` as of
    /// `now`. Waiting for memory stops the idle clock as work does; the
    /// write clock does not hear of it, since a peer that does not read is
    /// not a memory problem.
    pub(super) fn settle(&mut self, now: Instant, outstanding: Outstanding) {
        if outstanding.output {
            self.stalled_since.get_or_insert(now);
            self.idle_from = None;
        } else {
            self.stalled_since = None;
            if self.input_over || outstanding.input || outstanding.work || outstanding.memory {
                self.idle_from = None;
            } else {
                self.idle_from.get_or_insert(now);
            }
        }
    }

    /// When the next limit runs out, and which. At most one counts at a
    /// time.
    pub(super) fn deadline(&self) -> Option<(Instant, Expiry)> {
        let stalled = self
            .stalled_since
            .zip(self.limits.write_timeout)
            .map(|(since, limit)| (since + limit, Expiry::Stalled));
        let idle = self
            .idle_from
            .zip(self.limits.idle)
            .map(|(from, limit)| (from + limit, Expiry::Idle));
        stalled.or(idle)
    }

    /// The limit that has run out by `now`, if one has.
    pub(super) fn due(&self, now: Instant) -> Option<Expiry> {
        self.deadline()
            .filter(|(at, _)| *at <= now)
            .map(|(_, expiry)| expiry)
    }

    /// `expiry` ran out and the adapter acts on it. Its clock stops.
    pub(super) fn expire(&mut self, expiry: Expiry) {
        match expiry {
            Expiry::Idle => {
                self.idle_from = None;
                self.idled = true;
            }
            Expiry::Stalled => self.stalled_since = None,
        }
    }

    /// Whether the stream is done: the application ended its direction,
    /// its input is over or it declares itself `terminal`, and nothing is
    /// outstanding but input it will never take.
    pub(super) fn finished(&self, terminal: bool, outstanding: Outstanding) -> bool {
        self.output_over
            && (self.input_over || terminal)
            && !outstanding.output
            && !outstanding.work
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fictionet::{Entropy, Seed, SeededEntropy};

    use super::*;

    /// What a random step does to a lifetime.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        Settle(Outstanding),
        TookInput,
        Wrote,
        Interrupt,
    }

    fn any_step(rng: &SeededEntropy) -> Step {
        match rng.random_below(8) {
            0 => Step::TookInput,
            1 => Step::Wrote,
            2 => Step::Interrupt,
            _ => Step::Settle(Outstanding {
                output: rng.random_below(4) == 0,
                input: rng.random_below(4) == 0,
                work: rng.random_below(4) == 0,
                memory: rng.random_below(3) == 0,
            }),
        }
    }

    fn apply(lifetime: &mut Lifetime, now: Instant, step: Step) {
        match step {
            Step::Settle(outstanding) => lifetime.settle(now, outstanding),
            Step::TookInput => lifetime.took_input(),
            Step::Wrote => lifetime.wrote(),
            Step::Interrupt => lifetime.interrupt(),
        }
    }

    /// Random steps at random times, against a model of when the stream
    /// was last busy. After every step: the idle deadline is never earlier
    /// than an idle limit after the first settle that found the stream
    /// quiet since its last busy moment, busy being a byte read or written
    /// or a settle that found output, input, work or memory outstanding; a
    /// settle that finds it waiting for memory leaves no
    /// idle deadline; and a twin that sees the same steps without memory
    /// has the same write deadline at every step, so memory never moves it.
    #[test]
    fn the_idle_deadline_never_falls_inside_a_wait_for_memory() {
        let mut waits = 0;
        for seed in 0..256 {
            let rng = SeededEntropy::new(Seed::from_u64(seed));
            let limits = StreamLimits {
                idle: Some(Duration::from_millis(1 + rng.random_below(50))),
                write_timeout: Some(Duration::from_millis(1 + rng.random_below(50))),
            };
            let idle = limits.idle.unwrap();
            let mut lifetime = Lifetime::new(limits);
            let mut twin = Lifetime::new(limits);
            let mut now = Instant::ZERO;
            let mut quiet_from: Option<Instant> = None;
            for _ in 0..64 {
                now = now + Duration::from_millis(rng.random_below(30));
                let step = any_step(&rng);
                apply(&mut lifetime, now, step);
                let twin_step = match step {
                    Step::Settle(outstanding) => Step::Settle(Outstanding {
                        memory: false,
                        ..outstanding
                    }),
                    other => other,
                };
                apply(&mut twin, now, twin_step);
                // A byte read or written: the stream is not idle.
                if let Step::TookInput | Step::Wrote = step {
                    quiet_from = None;
                }
                if let Step::Settle(o) = step {
                    if o.output || o.input || o.work || o.memory {
                        quiet_from = None;
                    } else {
                        quiet_from.get_or_insert(now);
                    }
                    if o.memory && !o.output {
                        waits += 1;
                        assert_eq!(
                            lifetime.deadline(),
                            None,
                            "seed {seed}: an idle deadline while waiting for memory"
                        );
                    }
                }
                if let Some((at, Expiry::Idle)) = lifetime.deadline() {
                    let quiet = quiet_from.expect("an idle deadline only while quiet");
                    assert!(
                        at >= quiet + idle,
                        "seed {seed}: the idle deadline {at:?} is within the limit of {quiet:?}"
                    );
                }
                let stalled = |l: &Lifetime| {
                    l.deadline()
                        .filter(|(_, expiry)| *expiry == Expiry::Stalled)
                };
                assert_eq!(
                    stalled(&lifetime),
                    stalled(&twin),
                    "seed {seed}: memory moved the write deadline"
                );
            }
        }
        assert!(waits > 0, "the steps waited for memory");
    }
}

#[cfg(kani)]
#[path = "../../../../verification/layer-runtime/kani/lifetime.rs"]
mod proofs;
