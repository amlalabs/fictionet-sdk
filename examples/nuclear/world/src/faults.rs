//! Fault slots are bounded by the physical equipment and instrument list.
//! One fault per instrument is permitted. Clear it before replacing its kind.
//! Stuck values and biases use signed integer counts of that sensor's resolution.
//! A schedule has at most 32 entries. Entries at the same step run in array order.
//! A duplicate scheduled injection is a no-op, just like a rejected live command.
use crate::{
    command::Loop,
    sensors::{SENSOR_COUNT, Sensor},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessFault {
    FeedPumpTrip { pump: Loop },
    CoolantPumpTrip { pump: Loop },
    FeedValveStuck { line: Loop },
    CondenserCoolingLoss,
}
impl ProcessFault {
    pub const MAX_JSON_BYTES: usize = 34;
    pub const ALL: [Self; 7] = [
        Self::FeedPumpTrip { pump: Loop::A },
        Self::FeedPumpTrip { pump: Loop::B },
        Self::CoolantPumpTrip { pump: Loop::A },
        Self::CoolantPumpTrip { pump: Loop::B },
        Self::FeedValveStuck { line: Loop::A },
        Self::FeedValveStuck { line: Loop::B },
        Self::CondenserCoolingLoss,
    ];
    pub(crate) fn index(self) -> usize {
        match self {
            Self::FeedPumpTrip { pump } => pump.index(),
            Self::CoolantPumpTrip { pump } => 2 + pump.index(),
            Self::FeedValveStuck { line } => 4 + line.index(),
            Self::CondenserCoolingLoss => 6,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorFault {
    Quiet,
    Stuck { value: i16 },
    Bias { delta: i16 },
}
impl SensorFault {
    pub const MAX_JSON_BYTES: usize = 26;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    Process(ProcessFault),
    Sensor { sensor: Sensor, kind: SensorFault },
    TelemetryQuiet,
}
impl Fault {
    pub const MAX_JSON_BYTES: usize = 85;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultTarget {
    Process(ProcessFault),
    Sensor(Sensor),
    TelemetryQuiet,
}
impl FaultTarget {
    pub const MAX_JSON_BYTES: usize = 46;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultChange {
    Inject(Fault),
    Clear(FaultTarget),
    ClearAll,
}
impl FaultChange {
    pub const MAX_JSON_BYTES: usize = 96;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledFault {
    pub at_ms: u64,
    pub change: FaultChange,
}
impl ScheduledFault {
    pub const MAX_JSON_BYTES: usize = 136;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Faults {
    pub process: [Option<ProcessFault>; 7],
    pub sensors: [Option<SensorFault>; SENSOR_COUNT],
    pub telemetry_quiet: bool,
}
impl Default for Faults {
    fn default() -> Self {
        Self {
            process: [None; 7],
            sensors: [None; SENSOR_COUNT],
            telemetry_quiet: false,
        }
    }
}
impl Faults {
    pub const MAX_JSON_BYTES: usize = 861;
    pub(crate) fn has(&self, fault: ProcessFault) -> bool {
        self.process[fault.index()].is_some()
    }
}
