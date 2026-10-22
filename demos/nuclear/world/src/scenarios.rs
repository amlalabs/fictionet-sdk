//! Named initial conditions and ordered plant-time fault schedules.
use crate::{
    Config,
    command::Loop,
    faults::*,
    sensors::Sensor,
    stages::{FailureCause, Stage},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    Normal,
    LoopBUnattended,
    SteamLineBreak,
    StuckOpenRelief,
    StationBlackout,
    InjectionReturns,
}
impl Scenario {
    pub const ALL: [Self; 6] = [
        Self::Normal,
        Self::LoopBUnattended,
        Self::SteamLineBreak,
        Self::StuckOpenRelief,
        Self::StationBlackout,
        Self::InjectionReturns,
    ];
    pub const MAX_JSON_BYTES: usize = 19;

    pub fn config(self) -> Config {
        let mut config = Config {
            automatic_protection: !matches!(self, Self::LoopBUnattended | Self::SteamLineBreak),
            ..Config::default()
        };
        let mut next = 0;
        let mut add = |at_ms, change| {
            config.schedule[next] = Some(ScheduledFault { at_ms, change });
            next += 1;
        };
        let inject = |fault| FaultChange::Inject(Fault::Process(fault));
        match self {
            Self::Normal => {}
            Self::LoopBUnattended => {
                add(
                    10_000,
                    FaultChange::Inject(Fault::Sensor {
                        sensor: Sensor::HotLeg(Loop::B),
                        kind: SensorFault::Stuck { value: 3250 },
                    }),
                );
                add(
                    10_000,
                    inject(ProcessFault::CoolantPumpTrip { pump: Loop::B }),
                );
                add(60_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::A }));
                add(60_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::B }));
            }
            Self::SteamLineBreak => add(10_000, inject(ProcessFault::SteamLineBreak)),
            Self::StationBlackout => add(10_000, inject(ProcessFault::StationBlackout)),
            Self::StuckOpenRelief | Self::InjectionReturns => {
                add(10_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::A }));
                add(10_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::B }));
                add(10_000, inject(ProcessFault::ReliefStuckOpen));
                add(10_000, inject(ProcessFault::SafetyInjectionFailure));
                add(
                    4_440_000,
                    inject(ProcessFault::CoolantPumpTrip { pump: Loop::A }),
                );
                add(
                    4_440_000,
                    inject(ProcessFault::CoolantPumpTrip { pump: Loop::B }),
                );
                if self == Self::InjectionReturns {
                    add(
                        6_900_000,
                        FaultChange::Clear(FaultTarget::Process(
                            ProcessFault::SafetyInjectionFailure,
                        )),
                    );
                }
            }
        }
        config
    }
    pub fn expected_end(self) -> Option<(Stage, Option<FailureCause>)> {
        match self {
            Self::Normal | Self::InjectionReturns => None,
            Self::LoopBUnattended => {
                Some((Stage::ContainmentFailure, Some(FailureCause::HydrogenBurn)))
            }
            Self::SteamLineBreak => Some((Stage::ControlRoomUninhabitable, None)),
            Self::StuckOpenRelief => Some((Stage::FloorMeltThrough, None)),
            Self::StationBlackout => {
                Some((Stage::ContainmentFailure, Some(FailureCause::Overpressure)))
            }
        }
    }
    pub fn demo_speed(self) -> u16 {
        match self {
            Self::Normal | Self::SteamLineBreak => 1,
            Self::StuckOpenRelief => 600,
            _ => 60,
        }
    }
    pub fn title(self) -> &'static str {
        match self {
            Self::Normal => "Normal operation",
            Self::LoopBUnattended => "Loop B, unattended",
            Self::SteamLineBreak => "Steam line break",
            Self::StuckOpenRelief => "Stuck-open relief valve",
            Self::StationBlackout => "Station blackout",
            Self::InjectionReturns => "Injection returns",
        }
    }
    pub fn description(self) -> &'static str {
        match self {
            Self::Normal => "No faults; no expected end.",
            Self::LoopBUnattended => {
                "Hot leg B sensor sticks and coolant pump B trips, then both feed pumps trip; containment failure from a hydrogen burn is expected."
            }
            Self::SteamLineBreak => {
                "A steam line breaks; the control room is expected to become uninhabitable."
            }
            Self::StuckOpenRelief => {
                "Both feed pumps trip, a relief valve sticks open and safety injection fails, then both coolant pumps trip; floor melt-through is expected."
            }
            Self::StationBlackout => {
                "Station blackout removes AC power; containment failure from overpressure is expected."
            }
            Self::InjectionReturns => {
                "Both feed pumps trip, a relief valve sticks open and safety injection fails, then both coolant pumps trip; injection returns at 115 minutes and no end is expected."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InitialPower;

    #[test]
    fn wire_names_and_initial_conditions() {
        for (scenario, name) in Scenario::ALL.into_iter().zip([
            "normal",
            "loop_b_unattended",
            "steam_line_break",
            "stuck_open_relief",
            "station_blackout",
            "injection_returns",
        ]) {
            let json = serde_json::to_string(&scenario).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert!(json.len() <= Scenario::MAX_JSON_BYTES);
            assert_eq!(serde_json::from_str::<Scenario>(&json).unwrap(), scenario);
            let config = scenario.config();
            assert_eq!(config.initial_power, InitialPower::Full);
            assert_eq!(config.seed, 1);
            assert!(config.temperature_feedback);
            assert_eq!(
                config.automatic_protection,
                !matches!(
                    scenario,
                    Scenario::LoopBUnattended | Scenario::SteamLineBreak
                )
            );
            assert!(!scenario.description().contains('\n'));
        }
    }
    #[test]
    fn schedules_keep_every_fault_in_order() {
        let inject = |f| FaultChange::Inject(Fault::Process(f));
        let relief = vec![
            (10_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::A })),
            (10_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::B })),
            (10_000, inject(ProcessFault::ReliefStuckOpen)),
            (10_000, inject(ProcessFault::SafetyInjectionFailure)),
            (
                4_440_000,
                inject(ProcessFault::CoolantPumpTrip { pump: Loop::A }),
            ),
            (
                4_440_000,
                inject(ProcessFault::CoolantPumpTrip { pump: Loop::B }),
            ),
        ];
        let mut returns = relief.clone();
        returns.push((
            6_900_000,
            FaultChange::Clear(FaultTarget::Process(ProcessFault::SafetyInjectionFailure)),
        ));
        let expected = [
            vec![],
            vec![
                (
                    10_000,
                    FaultChange::Inject(Fault::Sensor {
                        sensor: Sensor::HotLeg(Loop::B),
                        kind: SensorFault::Stuck { value: 3250 },
                    }),
                ),
                (
                    10_000,
                    inject(ProcessFault::CoolantPumpTrip { pump: Loop::B }),
                ),
                (60_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::A })),
                (60_000, inject(ProcessFault::FeedPumpTrip { pump: Loop::B })),
            ],
            vec![(10_000, inject(ProcessFault::SteamLineBreak))],
            relief,
            vec![(10_000, inject(ProcessFault::StationBlackout))],
            returns,
        ];
        for (scenario, expected) in Scenario::ALL.into_iter().zip(expected) {
            let schedule = scenario.config().schedule;
            let count = expected.len();
            assert_eq!(
                schedule[..count]
                    .iter()
                    .map(|e| e.map(|f| (f.at_ms, f.change)))
                    .collect::<Vec<_>>(),
                expected.into_iter().map(Some).collect::<Vec<_>>()
            );
            assert!(schedule[count..].iter().all(Option::is_none));
        }
    }
}
