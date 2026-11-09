//! Runtime scheduling shared by applications on transport children.

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::Context;

use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, Budget, Children, CommandOf, Credited, Driver, EventOf, Layer, Port, Top,
};
use fictionet::stdlib::services::stack::{Job, Jobs};
use fictionet::time::Instant;

pub(crate) struct Applications<L: Layer>
where
    L::Work: Job<Done = L::Done>,
{
    driver: Driver<L>,
    jobs: Jobs<L::Work>,
    pending: VecDeque<EventOf<L::Lower>>,
}

/// Whether a layer has nothing open or queued, so that until an event comes
/// a step would move nothing.
pub(crate) trait Idle {
    fn idle(&self) -> bool {
        false
    }
}

impl<B, K, O> Idle for Children<B, K, O>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    fn idle(&self) -> bool {
        self.is_idle()
    }
}

impl<L: Layer + Idle> Applications<L>
where
    L::Work: Job<Done = L::Done>,
    L::Error: std::fmt::Display,
{
    pub(crate) fn new(fcx: &Cx, layer: L) -> Self {
        // Routing has engine count limits; each application has its own byte budget.
        let mut driver = Driver::new(layer, Arc::new(fcx.clone()), Budget::unlimited(), fcx.now());
        driver.keep_observations(0);
        Self {
            driver,
            jobs: Jobs::new(),
            pending: VecDeque::new(),
        }
    }

    /// With no application open, no work and nothing held, only a new event
    /// can move anything.
    pub(crate) fn idle(&self) -> bool {
        self.pending.is_empty()
            && self.jobs.is_empty()
            && !self.driver.holds_output()
            && self.driver.layer().idle()
    }

    pub(crate) fn poll(
        &mut self,
        fcx: &Cx,
        now: Instant,
        cx: &mut Context<'_>,
        mut events: impl FnMut(&mut VecDeque<EventOf<L::Lower>>),
        command: impl FnMut(CommandOf<L::Lower>) -> Admit<CommandOf<L::Lower>>,
    ) -> fictionet::Result<bool> {
        let mut command = command;
        if self.idle() {
            events(&mut self.pending);
            if self.pending.is_empty() {
                return Ok(false);
            }
        }
        self.driver.set_now(now);
        let mut exhausted = false;
        let mut intake = 64;
        let mut blocked = false;
        // As in the stream runner, existing work observes transport wakeups
        // before queued input ends its child lifetime. Work cancelled by that
        // input is removed before the next poll. Work handed over in a turn
        // is polled in the next, so what it finishes at once is answered
        // before the transport sends what this poll wrote.
        let mut poll_jobs = true;
        for turn in 0..64 {
            let mut moved = false;
            if poll_jobs {
                moved |= self
                    .jobs
                    .poll(Some(fcx), cx, |done| self.driver.complete(done))
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            }
            if self.pending.is_empty() {
                events(&mut self.pending);
            }
            self.driver
                .run()
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            moved |= self.driver.send_below(&mut command);
            while intake > 0
                && let Some(event) = self.pending.pop_front()
            {
                match self
                    .driver
                    .deliver(event)
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?
                {
                    Admit::Blocked(event) => {
                        self.pending.push_front(event);
                        blocked = true;
                        break;
                    }
                    _ => {
                        intake -= 1;
                        blocked = false;
                        moved = true;
                    }
                }
            }
            poll_jobs = self.jobs.take(&mut self.driver);
            if self.jobs.budget_exhausted() {
                return Err(fictionet::Error::msg("application work budget exhausted"));
            }
            if !(moved || poll_jobs) {
                break;
            }
            exhausted = turn == 63;
        }
        if self.pending.is_empty() {
            events(&mut self.pending);
        }
        Ok(exhausted || (!self.pending.is_empty() && !blocked) || self.driver.exhausted())
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.driver.deadline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::layer::{Env, MessageCommand, MessageEvent, Messages, Top};
    use std::convert::Infallible;
    use std::time::Duration;

    struct Waiting {
        at: Instant,
        ready: bool,
        received: usize,
    }
    impl Idle for Waiting {}
    impl Layer for Waiting {
        type Lower = Messages<(), ()>;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: MessageEvent<()>,
        ) -> Result<Admit<MessageEvent<()>>, Infallible> {
            if !self.ready {
                return Ok(Admit::Blocked(event));
            }
            self.received += 1;
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn on_timer(&mut self, _: &mut Env<'_, Infallible>, _: ()) -> Result<bool, Infallible> {
            self.ready = true;
            Ok(true)
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            (!self.ready).then_some((self.at, ()))
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<MessageCommand<()>> {
            None
        }
    }

    #[test]
    fn refused_input_waits_for_readiness_without_requesting_a_busy_poll() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let delay = Duration::from_millis(5);
                let at = cx.now() + delay;
                let mut applications = Applications::new(
                    &cx,
                    Waiting {
                        at,
                        ready: false,
                        received: 0,
                    },
                );
                let mut source = VecDeque::from([MessageEvent::Message(())]);
                let busy = applications.poll(
                    &cx,
                    cx.now(),
                    &mut Context::from_waker(std::task::Waker::noop()),
                    |pending| std::mem::swap(pending, &mut source),
                    |_| Admit::Taken,
                )?;
                assert!(!busy, "refusal must wait for a timer or a wake");
                assert_eq!(applications.deadline(), Some(at));
                assert_eq!(applications.pending.len(), 1);
                cx.sleep(delay).await?;
                applications.poll(
                    &cx,
                    cx.now(),
                    &mut Context::from_waker(std::task::Waker::noop()),
                    |pending| std::mem::swap(pending, &mut source),
                    |_| Admit::Taken,
                )?;
                assert!(applications.pending.is_empty());
                assert_eq!(applications.driver.layer().received, 1);
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}
