//! The World menu's commands and the authoritative route state.

use border_world::routing::{Applied, Rejection, RouteState, Routing, SetImpostor, SetRoute};
use border_world::scenario::{Scenario, Task, Variant, parse_prefix};
use fictionet::Cx;
use fictionet_observe::page::{
    CommandLimits, CommandPort, Page, Rejected, StateLimits, StateTopic,
};
use serde::Deserialize;
use std::sync::Arc;

/// What the World menu asks of the world. Each carries the revision of the
/// route state the menu showed.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Normal or hijacked.
    Route {
        mode: Variant,
        expected_revision: u64,
    },
    /// Whether the impostor answers at the bank's address in the hijack.
    Impostor { on: bool, expected_revision: u64 },
    /// The route back to normal, the impostor on, and the picture cleared.
    Restart { expected_revision: u64 },
}

pub type Port = CommandPort<Command, Applied>;

#[derive(Clone)]
pub struct Control {
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
            view: super::view::Projection::new(Arc::new(scenario.clone())),
            port: Port::new(CommandLimits::default()),
            state: StateTopic::new(StateLimits {
                max_bytes: RouteState::MAX_JSON_BYTES,
            }),
        };
        control.state.publish(
            fictionet::time::Instant::ZERO,
            &RouteState::new(scenario, 0, 0),
        )?;
        Ok(control)
    }

    /// The app: the guest's Screen and Terminal beside the route picture,
    /// with the World menu's commands and the route state.
    pub fn page(&self, page: Page) -> Page {
        page.command("world", self.port.clone())
            .state("routing", self.state.clone())
            .custom(
                "Border",
                "export { mount } from '../assets/border/view.mjs';\n",
                self.view.topic.clone(),
            )
            .asset(
                "border/view.mjs",
                "text/javascript",
                include_bytes!("view.mjs").to_vec(),
            )
            .asset(
                "border/picture.mjs",
                "text/javascript",
                include_bytes!("picture.mjs").to_vec(),
            )
            .asset(
                "border/style.css",
                "text/css",
                include_bytes!("style.css").to_vec(),
            )
            .workspace("Border")
            .app()
    }

    /// Applies a World menu command and publishes the new route state, or
    /// says why the world rejects it. A restart also clears the picture.
    pub fn apply(
        &self,
        cx: &Cx,
        routing: &Routing,
        command: &Command,
    ) -> fictionet::Result<Result<Applied, Rejected>> {
        let result = match *command {
            Command::Route {
                mode,
                expected_revision,
            } => routing.apply(
                cx,
                SetRoute {
                    mode,
                    expected_revision,
                },
            ),
            Command::Impostor {
                on,
                expected_revision,
            } => routing.set_impostor(
                cx,
                SetImpostor {
                    on,
                    expected_revision,
                },
            ),
            Command::Restart { expected_revision } => routing.restart(cx, expected_revision),
        };
        let rejected = match result {
            Ok(applied) => {
                if matches!(command, Command::Restart { .. }) {
                    self.view.clear(cx.now());
                }
                self.state.publish(cx.now(), &routing.state())?;
                return Ok(Ok(applied));
            }
            Err(rejected) => rejected,
        };
        Ok(Err(match rejected.reason {
            Rejection::StaleRevision => Rejected::StaleRevision {
                current: rejected.revision,
            },
            Rejection::AlreadyInMode => Rejected::Invalid {
                message: match command {
                    Command::Route { mode, .. } => format!(
                        "The route is already {}.",
                        match mode {
                            Variant::Legitimate => "normal",
                            Variant::Hijack => "hijacked",
                        }
                    ),
                    Command::Impostor { on, .. } => {
                        format!(
                            "The impostor is already {}.",
                            if *on { "on" } else { "off" }
                        )
                    }
                    Command::Restart { .. } => "The run is already restarted.".into(),
                },
            },
        }))
    }

    pub async fn serve(self, cx: Cx, routing: Routing) -> fictionet::Result {
        fictionet_demo::kit::serve_commands(&cx, &self.port, |command| {
            self.apply(&cx, &routing, command)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::Command;
    use border_world::scenario::Variant;

    #[test]
    fn the_menu_sends_one_of_three_commands_with_its_revision() {
        let parse = |text: &str| serde_json::from_str::<Command>(text).ok();
        assert_eq!(
            parse(r#"{"command":"route","mode":"hijack","expected_revision":3}"#),
            Some(Command::Route {
                mode: Variant::Hijack,
                expected_revision: 3
            })
        );
        assert_eq!(
            parse(r#"{"command":"impostor","on":false,"expected_revision":4}"#),
            Some(Command::Impostor {
                on: false,
                expected_revision: 4
            })
        );
        assert_eq!(
            parse(r#"{"command":"restart","expected_revision":5}"#),
            Some(Command::Restart {
                expected_revision: 5
            })
        );
        for bad in [
            r#"{"command":"route","mode":"hijack"}"#,
            r#"{"command":"route","mode":"other","expected_revision":1}"#,
            r#"{"command":"restart","expected_revision":1,"extra":true}"#,
            r#"{"mode":"hijack","expected_revision":1}"#,
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
