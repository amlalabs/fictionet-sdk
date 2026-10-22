//! Bounded operator commands. Position units are tenths of a percent for rods
//! and permille for valves. Loop and pump indices cannot name a third loop.
//! Accepted controls change demands at the current time; physical motion and
//! fault effects occur on the next plant step. Counters saturate at u64::MAX.
use crate::faults::FaultChange;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Loop {
    A,
    B,
}
impl Loop {
    pub const ALL: [Self; 2] = [Self::A, Self::B];
    pub const MAX_JSON_BYTES: usize = 3;
    pub(crate) fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pump {
    Coolant(Loop),
    MainFeed(Loop),
    AuxiliaryFeed,
    CirculatingWater,
    SafetyInjection,
}
impl Pump {
    pub const MAX_JSON_BYTES: usize = 19;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Valve {
    Feed(Loop),
    Turbine,
    SteamDump,
    PressurizerSpray,
}
impl Valve {
    pub const MAX_JSON_BYTES: usize = 19;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Controller {
    FeedLevel(Loop),
    PressurizerPressure,
    SteamDump,
}
impl Controller {
    pub const MAX_JSON_BYTES: usize = 22;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Automatic,
    Manual,
}
impl Mode {
    pub const MAX_JSON_BYTES: usize = 11;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    RodDemand { tenths_percent: u16 },
    ManualTrip,
    ResetTrip,
    Pump { pump: Pump, running: bool },
    ValveDemand { valve: Valve, permille: u16 },
    Controller { controller: Controller, mode: Mode },
    Heaters { on: bool },
    Relief { open: bool },
    ReliefBlock { closed: bool },
    SteamIsolation { closed: bool },
    AcknowledgeAlarms,
}
impl Command {
    pub const MAX_JSON_BYTES: usize = 71;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultCommand {
    pub change: FaultChange,
    pub expected_revision: u64,
}
impl FaultCommand {
    pub const MAX_JSON_BYTES: usize = 52 + FaultChange::MAX_JSON_BYTES;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    pub at_ms: u64,
}
impl Applied {
    pub const MAX_JSON_BYTES: usize = 62;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    StaleRevision,
    OutOfRange,
    Tripped,
    TripConditionPresent,
    Faulted,
    WrongMode,
    AlreadyActive,
    NotActive,
}
impl Rejection {
    pub const MAX_JSON_BYTES: usize = 24;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejected {
    pub reason: Rejection,
    pub revision: u64,
}
impl Rejected {
    pub const MAX_JSON_BYTES: usize = 67;
}
