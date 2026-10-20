use fakewiki_world::pages::diff::{Diff, MAX_DIFF_BYTES};
use fakewiki_world::tamper::{self, Command, Reply, TamperState, Tampering};
use fictionet::Cx;
use fictionet_observe::page::{
    Action, Column, CommandLimits, CommandPort, EventFilter, Format, Page, Rejected, StateLimits,
    StateTopic,
};
use serde_json::json;

#[derive(Clone)]
pub struct Controls {
    pub commands: CommandPort<Command, Reply>,
    pub state: StateTopic<TamperState>,
    pub diff: StateTopic<Diff>,
}

impl Controls {
    pub fn new() -> Self {
        Self {
            commands: CommandPort::new(CommandLimits::default()),
            state: StateTopic::new(StateLimits {
                max_bytes: tamper::MAX_TAMPER_STATE_BYTES,
                deltas: 0,
            }),
            diff: StateTopic::new(StateLimits {
                max_bytes: MAX_DIFF_BYTES,
                deltas: 0,
            }),
        }
    }

    pub fn page(&self, page: Page) -> Page {
        page.standard_panels()
            .control(
                "Tamper",
                self.commands.clone(),
                [true, false]
                    .map(|on| Action {
                        label: if on { "Turn on" } else { "Turn off" }.into(),
                        command: json!({"type":"set_tampering", "on":on}),
                    })
                    .to_vec(),
            )
            .control_state(self.state.clone())
            .state("diff", self.diff.clone())
            .event_table(
                "Reads (scripted reader)",
                EventFilter {
                    source: Some("http".into()),
                    kind: Some("request".into()),
                    field_present: Some("tamper_revision".into()),
                    host: Some(super::HOST.into()),
                    ..EventFilter::default()
                },
                vec![
                    Column::new("Time", "/at").format(Format::Time),
                    Column::new("Host", "/fields/host"),
                    Column::new("Path", "/fields/path"),
                    Column::new("Source", "/fields/source"),
                    Column::new("Served", "/fields/served"),
                    Column::new("Revision", "/fields/tamper_revision").format(Format::Number),
                ],
            )
    }

    pub(super) fn publish(&self, cx: &Cx, tampering: &Tampering) -> fictionet::Result {
        let state = tampering.state();
        self.state.publish(cx.now(), &state)?;
        self.diff.publish(cx.now(), &Diff::new(state))?;
        Ok(())
    }

    pub(super) fn apply(
        &self,
        cx: &Cx,
        tampering: &Tampering,
        command: Command,
    ) -> fictionet::Result<Reply> {
        let reply = tampering.apply(cx, command);
        if matches!(reply, Reply::Applied { .. }) {
            self.publish(cx, tampering)?;
        }
        Ok(reply)
    }

    pub fn start(self, cx: &Cx, tampering: Tampering) -> fictionet::Result {
        self.publish(cx, &tampering)?;
        cx.spawn(move |cx| async move {
            while let Some(command) = cx.race(None, self.commands.recv()).await? {
                let reply = self.apply(&cx, &tampering, command.command)?;
                match reply {
                    Reply::Applied { .. } => command.reply(&cx, reply),
                    Reply::Rejected(tamper::Rejection::StaleRevision { current, .. }) => {
                        command.reject(&cx, Rejected::StaleRevision { current });
                    }
                }
            }
            Ok(())
        });
        Ok(())
    }
}
