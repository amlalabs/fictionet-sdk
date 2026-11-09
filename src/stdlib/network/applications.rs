//! Runtime scheduling shared by applications on transport children.

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::Context;

use fictionet::Cx;
use fictionet::stdlib::layer::{Admit, Budget, CommandOf, Driver, EventOf, Layer};
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

impl<L: Layer> Applications<L>
where
    L::Work: Job<Done = L::Done>,
    L::Error: std::fmt::Display,
{
    pub(crate) fn new(fcx: &Cx, layer: L) -> Self {
        let mut driver = Driver::new(layer, Arc::new(fcx.clone()), Budget::unlimited(), fcx.now());
        driver.keep_observations(0);
        Self {
            driver,
            jobs: Jobs::new(),
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn poll(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        mut events: impl FnMut(&mut VecDeque<EventOf<L::Lower>>),
        command: impl FnMut(CommandOf<L::Lower>) -> Admit<CommandOf<L::Lower>>,
    ) -> fictionet::Result<bool> {
        let mut command = command;
        self.driver.set_now(fcx.now());
        // As in the stream runner, existing work observes transport wakeups
        // before queued input ends its child lifetime. Work cancelled by that
        // input is removed before the next poll.
        let completed = self
            .jobs
            .poll(Some(fcx), cx, |done| self.driver.complete(done))
            .map_err(|e| fictionet::Error::msg(e.to_string()))?;
        let mut exhausted = false;
        let mut intake = 64;
        let mut blocked = false;
        for turn in 0..64 {
            if self.pending.is_empty() {
                events(&mut self.pending);
            }
            self.driver
                .run()
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            let mut moved = self.driver.send_below(&mut command);
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
            if !moved {
                break;
            }
            exhausted = turn == 63;
        }
        self.jobs.take(&mut self.driver);
        let moved = self
            .jobs
            .poll(Some(fcx), cx, |done| self.driver.complete(done))
            .map_err(|e| fictionet::Error::msg(e.to_string()))?;
        if self.jobs.budget_exhausted() {
            return Err(fictionet::Error::msg("application work budget exhausted"));
        }
        if self.pending.is_empty() {
            events(&mut self.pending);
        }
        Ok(completed
            || exhausted
            || moved
            || (!self.pending.is_empty() && !blocked)
            || self.driver.exhausted())
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
        fn on_timer(&mut self, _: &mut Env<'_, Infallible>, _: ()) -> Result<(), Infallible> {
            self.ready = true;
            Ok(())
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            (!self.ready).then_some((self.at, ()))
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn take_command(&mut self) -> Option<MessageCommand<()>> {
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
