use super::*;
use fictionet::stdlib::layer::{Children, Datagrams, Layer};
use fictionet::stdlib::services::stack::{Boxed, Jobs};
use std::collections::VecDeque;

type Application = Boxed<Datagrams<SocketAddr>>;
pub(super) type ApplicationEvent = MuxEvent<Datagrams<SocketAddr>, Control, (Application, Budget)>;
type ApplicationsLayer = Children<Application, Control, (Application, Budget)>;

pub(super) struct Applications {
    driver: Driver<ApplicationsLayer>,
    jobs: Jobs<<ApplicationsLayer as Layer>::Work>,
    pending: VecDeque<ApplicationEvent>,
}

impl Applications {
    pub(super) fn new(fcx: &Cx) -> Self {
        let children = Children::new(4096, 1, |_, (application, _), _| application)
            .budgets(|_, (_, budget): &(Application, Budget), _| budget.clone());
        let mut driver = Driver::new(
            children,
            Arc::new(fcx.clone()),
            Budget::unlimited(),
            fcx.now(),
        );
        driver.keep_observations(0);
        Self {
            driver,
            jobs: Jobs::new(),
            pending: VecDeque::new(),
        }
    }

    pub(super) fn poll(
        &mut self,
        fcx: &Cx,
        shared: &Shared,
        cx: &mut std::task::Context<'_>,
    ) -> fictionet::Result<bool> {
        self.driver.set_now(fcx.now());
        let mut exhausted = false;
        for turn in 0..64 {
            if self.pending.is_empty() {
                std::mem::swap(
                    &mut self.pending,
                    &mut shared.inner.lock().application_events,
                );
            }
            let mut moved = self
                .driver
                .run()
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            moved |= self
                .driver
                .send_below(|command| shared.with(|inner| inner.application_command(command)));
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
        Ok(exhausted
            || moved
            || !self.pending.is_empty()
            || self.driver.exhausted()
            || !shared.inner.lock().application_events.is_empty())
    }

    pub(super) fn deadline(&self) -> Option<fictionet::time::Instant> {
        self.driver.deadline()
    }
}
