//! Plant time from caller-supplied run time, with pause and reset commands.

use crate::scenarios::Scenario;
use serde::{Deserialize, Serialize};

/// A run-time anchor and the plant time reached at that anchor.
#[derive(Clone, Debug)]
pub struct Pace {
    run_at_change: u64,
    plant_at_change: u64,
    speed: u16,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            run_at_change: 0,
            plant_at_change: 0,
            speed: 1,
        }
    }
}

/// Commands accepted by the viewer's scenario port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCommand {
    Start {
        scenario: Scenario,
        speed: Option<u16>,
    },
    Speed {
        speed: u16,
    },
}

/// The applied settings and plant time. Speed changes omit the scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<Scenario>,
    pub speed: u16,
    pub at_ms: u64,
}

/// A refused speed leaves both the plant and pace unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refused {
    InvalidSpeed,
}

pub type Reply = Result<Applied, Refused>;

impl Pace {
    pub fn target(&self, run_ms: u64) -> u64 {
        self.plant_at_change.saturating_add(
            u64::from(self.speed).saturating_mul(run_ms.saturating_sub(self.run_at_change)),
        )
    }

    pub fn speed(&self) -> u16 {
        self.speed
    }

    /// Rebase on the plant time actually reached, including any partial tick.
    pub fn set_speed(&mut self, run_ms: u64, plant_ms: u64, speed: u16) -> Result<(), Refused> {
        if !matches!(speed, 0 | 1 | 10 | 60 | 600) {
            return Err(Refused::InvalidSpeed);
        }
        self.run_at_change = run_ms;
        self.plant_at_change = plant_ms;
        self.speed = speed;
        Ok(())
    }

    pub fn reset(&mut self, run_ms: u64, speed: u16) -> Result<(), Refused> {
        self.set_speed(run_ms, 0, speed)
    }

    /// Validate and apply pacing. The caller resets the plant for a start reply.
    pub fn apply(&mut self, command: ScenarioCommand, run_ms: u64, plant_ms: u64) -> Reply {
        let (scenario, speed, at_ms) = match command {
            ScenarioCommand::Start { scenario, speed } => {
                (Some(scenario), speed.unwrap_or(scenario.demo_speed()), 0)
            }
            ScenarioCommand::Speed { speed } => (None, speed, plant_ms),
        };
        self.set_speed(run_ms, at_ms, speed)?;
        Ok(Applied {
            scenario,
            speed,
            at_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_changes_pause_and_reset_rebase() {
        let mut pace = Pace::default();
        assert_eq!(pace.target(1_000), 1_000);
        pace.set_speed(1_000, 950, 60).unwrap();
        assert_eq!(pace.target(1_500), 30_950);
        pace.set_speed(1_500, 30_950, 0).unwrap();
        assert_eq!(pace.target(20_000), 30_950);
        pace.reset(20_000, 600).unwrap();
        assert_eq!(pace.target(20_000), 0);
        assert_eq!(pace.target(20_050), 30_000);
    }

    #[test]
    fn commands_parse_and_reply_with_applied_settings() {
        let mut pace = Pace::default();
        let start =
            serde_json::from_str(r#"{"start":{"scenario":"stuck_open_relief","speed":600}}"#)
                .unwrap();
        assert_eq!(
            pace.apply(start, 10, 50).unwrap(),
            Applied {
                scenario: Some(Scenario::StuckOpenRelief),
                speed: 600,
                at_ms: 0
            }
        );
        let speed = serde_json::from_str(r#"{"speed":{"speed":60}}"#).unwrap();
        let reply = pace.apply(speed, 20, 6_000);
        assert_eq!(
            serde_json::to_value(reply).unwrap(),
            serde_json::json!({"Ok":{"speed":60,"at_ms":6000}})
        );
        for scenario in Scenario::ALL {
            let command =
                serde_json::from_value(serde_json::json!({"start":{"scenario":scenario}})).unwrap();
            let applied = pace.apply(command, 30, 60).unwrap();
            assert_eq!(applied.scenario, Some(scenario));
            assert_eq!(applied.speed, scenario.demo_speed());
            assert_eq!(applied.at_ms, 0);
        }
        assert!(
            serde_json::from_str::<ScenarioCommand>(r#"{"start":{"scenario":"missing"}}"#).is_err()
        );
    }

    #[test]
    fn refused_commands_leave_pace_unchanged() {
        let mut pace = Pace::default();
        for command in [
            ScenarioCommand::Speed { speed: 30 },
            ScenarioCommand::Start {
                scenario: Scenario::Normal,
                speed: Some(30),
            },
        ] {
            assert_eq!(pace.apply(command, 100, 50), Err(Refused::InvalidSpeed));
            assert_eq!(pace.speed(), 1);
            assert_eq!(pace.target(200), 200);
        }
        assert_eq!(
            serde_json::to_value(Err::<Applied, _>(Refused::InvalidSpeed)).unwrap(),
            serde_json::json!({"Err":"invalid_speed"})
        );
    }
}
