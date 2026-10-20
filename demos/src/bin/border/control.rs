//! The page's routing mailbox and authoritative projections.

use border_world::routing::{Applied, Rejection, RouteState, Routing, SetRoute};
use border_world::scenario::{Scenario, Task, Variant, parse_prefix};
use fictionet::Cx;
use fictionet_observe::page::{
    Action, CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic,
};
use serde_json::json;
use std::sync::Arc;

pub type Port = CommandPort<SetRoute, Applied>;

#[derive(Clone)]
pub struct Control {
    pub results: StateTopic<super::results::Results>,
    pub view: super::view::Projection,
    pub port: Port,
    pub state: StateTopic<RouteState>,
}

pub fn scenario() -> Arc<Scenario> {
    Arc::new(Scenario::new(
        Variant::Legitimate,
        Task::Login,
        parse_prefix("192.168.1.0/24").unwrap(),
    ))
}

impl Control {
    pub fn new(scenario: &Scenario) -> fictionet::Result<Self> {
        let control = Self {
            results: super::results::Writer::<Vec<u8>>::topic(),
            view: super::view::Projection::new(Arc::new(scenario.clone())),
            port: Port::new(CommandLimits::default()),
            state: StateTopic::new(StateLimits {
                max_bytes: RouteState::MAX_JSON_BYTES,
            }),
        };
        control.publish(
            fictionet::time::Instant::ZERO,
            &RouteState::new(scenario, 0, 0),
        )?;
        Ok(control)
    }

    pub fn page(&self, page: Page) -> Page {
        page.custom(
            "Border",
            include_str!("border.mjs"),
            self.view.topic.clone(),
        )
        .asset(
            "border.css",
            "text/css",
            include_bytes!("border.css").to_vec(),
        )
        .workspace("Border")
        .custom("Results", include_str!("results.mjs"), self.results.clone())
        .custom("TLS", include_str!("tls.mjs"), self.view.tls.topic.clone())
        .control(
            "Routing",
            self.port.clone(),
            vec![
                Action {
                    label: "Normal".into(),
                    command: json!({"mode":"legitimate"}),
                },
                Action {
                    label: "Hijacked".into(),
                    command: json!({"mode":"hijack"}),
                },
            ],
        )
        .control_state(self.state.clone())
    }

    fn publish(&self, at: fictionet::time::Instant, state: &RouteState) -> fictionet::Result {
        self.state.publish(at, state)?;
        Ok(())
    }

    /// Applies a route command and publishes the new route, or says why the
    /// page rejects it.
    pub fn apply(
        &self,
        cx: &Cx,
        routing: &Routing,
        route: &SetRoute,
    ) -> fictionet::Result<Result<Applied, Rejected>> {
        let rejected = match routing.apply(cx, route.clone()) {
            Ok(applied) => {
                self.publish(cx.now(), &routing.state())?;
                return Ok(Ok(applied));
            }
            Err(rejected) => rejected,
        };
        Ok(Err(match rejected.reason {
            Rejection::StaleRevision => Rejected::StaleRevision {
                current: rejected.revision,
            },
            Rejection::AlreadyInMode => Rejected::Invalid {
                message: format!(
                    "the route is already {} (revision {})",
                    match rejected.mode {
                        Variant::Legitimate => "Normal",
                        Variant::Hijack => "Hijacked",
                    },
                    rejected.revision
                ),
            },
        }))
    }

    pub async fn serve(self, cx: Cx, routing: Routing) -> fictionet::Result {
        fictionet_demo::kit::serve_commands(&cx, &self.port, |route| {
            self.apply(&cx, &routing, route)
        })
        .await
    }
}
