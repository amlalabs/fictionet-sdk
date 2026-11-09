use fictionet::time::Instant;

use super::StreamLimits;

/// When a stream gives up on its peer, and when it is done: the policy
/// [`Session`](super::Session) and the stream adapter share. Each adapter
/// moves the bytes and reports what happened; this decides.
///
/// The idle limit counts while the stream waits for the peer: input is
/// open and none is held, no output is held, and no work runs. It starts
/// again each time the stream begins to wait. The write limit counts while
/// output is held, from the last byte that went out.
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
#[derive(Clone, Copy)]
pub(super) struct Outstanding {
    /// Output the transport has not taken.
    pub(super) output: bool,
    /// Input the application has not taken.
    pub(super) input: bool,
    /// Work the application handed over that has not finished.
    pub(super) work: bool,
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

    /// The application took input or bytes went out: both limits count
    /// again from the next [`settle`](Self::settle).
    pub(super) fn progress(&mut self) {
        self.idle_from = None;
        self.stalled_since = None;
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
    /// `now`.
    pub(super) fn settle(&mut self, now: Instant, outstanding: Outstanding) {
        if outstanding.output {
            self.stalled_since.get_or_insert(now);
            self.idle_from = None;
        } else {
            self.stalled_since = None;
            if self.input_over || outstanding.input || outstanding.work {
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
