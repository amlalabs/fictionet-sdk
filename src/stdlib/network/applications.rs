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
        for turn in 0..64 {
            if self.pending.is_empty() {
                events(&mut self.pending);
            }
            self.driver
                .run()
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            let mut moved = self.driver.send_below(&mut command);
            if let Some(event) = self.pending.pop_front() {
                match self
                    .driver
                    .deliver(event)
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?
                {
                    Admit::Blocked(event) => {
                        self.pending.push_front(event);
                        break;
                    }
                    _ => moved = true,
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
        Ok(completed || exhausted || moved || !self.pending.is_empty() || self.driver.exhausted())
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.driver.deadline()
    }
}
