use super::*;
use fictionet::stdlib::layer::{Children, Layer};
use fictionet::stdlib::services::stack::{Boxed, Jobs};

pub(crate) struct Application {
    pub(crate) make: Arc<dyn Fn(TcpOpening, GoneWatch, &Budget) -> Boxed + Send + Sync>,
    pub(crate) budget: Arc<dyn Fn(&TcpOpening, &GoneWatch) -> Budget + Send + Sync>,
}

type Opening = (TcpOpening, Arc<Application>);
pub(super) type ApplicationEvent = MuxEvent<ByteStream, Messages<TcpNotice, TcpControl>, Opening>;
type ChildrenLayer = Children<Boxed, Messages<TcpNotice, TcpControl>, Opening>;

/// Runtime work for applications attached to the transport's actual children.
/// No connection facade or stream runner lies between these layers.
pub(super) struct Applications {
    driver: Driver<ChildrenLayer>,
    jobs: Jobs<<ChildrenLayer as Layer>::Work>,
    pending: VecDeque<ApplicationEvent>,
}

impl Applications {
    pub(super) fn new(fcx: &Cx, shared: &Arc<Shared>) -> Self {
        let factory = shared.clone();
        let budgets = shared.clone();
        let children = Children::new(
            4096,
            16 * 1024,
            move |id, (opening, application): Opening, budget| {
                let socket = GoneWatch {
                    shared: factory.clone(),
                    id,
                };
                (application.make)(opening, socket, budget)
            },
        )
        .budgets(move |id, (opening, application), _| {
            (application.budget)(
                opening,
                &GoneWatch {
                    shared: budgets.clone(),
                    id,
                },
            )
        });
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
        cx: &mut Context<'_>,
    ) -> fictionet::Result<bool> {
        self.driver.set_now(fcx.now());
        let mut exhausted = false;
        for turn in 0..64 {
            if self.pending.is_empty() {
                std::mem::swap(
                    &mut self.pending,
                    &mut shared.state.lock().routes.application_events,
                );
            }
            let mut moved = self
                .driver
                .run()
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            moved |= self
                .driver
                .send_below(|command| shared.state.lock().offer(command));
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
            || !shared.state.lock().routes.application_events.is_empty())
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.driver.deadline()
    }
}
