//! Display channels sample every 250 ms. Temperature elements have a 3 s lag.
//! Other channels have no lag. Noise is uniform within 0.6 resolution counts,
//! using SplitMix64 and its upper 53 bits. Quantization rounds half away from
//! zero using integer conversion, so no platform math library is involved.
//! Fault values are counts, not engineering units: 3250 means 325.0 C.
//! Quiet channels retain both value and timestamp; stuck channels stay fresh.
//! Whole telemetry quiet also freezes all sampled equipment status. Controller
//! modes remain live control-system state, separate from field telemetry.
//! Local process controllers and protection use separate noiseless channels.
//! Display noise therefore never changes the true plant trajectory.
use crate::{
    command::Loop,
    faults::{Faults, SensorFault},
    snapshot::ReportedStatus,
};
use serde::{Deserialize, Serialize};

pub const SAMPLE_MS: u64 = 250;
pub const SENSOR_COUNT: usize = 22;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensor {
    NeutronPower,
    RodPosition,
    HotLeg(Loop),
    ColdLeg(Loop),
    PressurizerPressure,
    PressurizerLevel,
    CoolantFlow(Loop),
    SteamGeneratorLevel(Loop),
    SteamPressure,
    SteamFlow(Loop),
    FeedFlow(Loop),
    TurbineValve,
    GeneratorOutput,
    CondenserPressure,
    CoreExitTemperature,
    ShutdownRodPosition,
}
impl Sensor {
    pub const MAX_JSON_BYTES: usize = 29;
    pub const ALL: [Self; SENSOR_COUNT] = [
        Self::NeutronPower,
        Self::RodPosition,
        Self::HotLeg(Loop::A),
        Self::HotLeg(Loop::B),
        Self::ColdLeg(Loop::A),
        Self::ColdLeg(Loop::B),
        Self::PressurizerPressure,
        Self::PressurizerLevel,
        Self::CoolantFlow(Loop::A),
        Self::CoolantFlow(Loop::B),
        Self::SteamGeneratorLevel(Loop::A),
        Self::SteamGeneratorLevel(Loop::B),
        Self::SteamPressure,
        Self::SteamFlow(Loop::A),
        Self::SteamFlow(Loop::B),
        Self::FeedFlow(Loop::A),
        Self::FeedFlow(Loop::B),
        Self::TurbineValve,
        Self::GeneratorOutput,
        Self::CondenserPressure,
        Self::CoreExitTemperature,
        Self::ShutdownRodPosition,
    ];
    pub fn index(self) -> usize {
        match self {
            Self::NeutronPower => 0,
            Self::RodPosition => 1,
            Self::HotLeg(l) => 2 + l.index(),
            Self::ColdLeg(l) => 4 + l.index(),
            Self::PressurizerPressure => 6,
            Self::PressurizerLevel => 7,
            Self::CoolantFlow(l) => 8 + l.index(),
            Self::SteamGeneratorLevel(l) => 10 + l.index(),
            Self::SteamPressure => 12,
            Self::SteamFlow(l) => 13 + l.index(),
            Self::FeedFlow(l) => 15 + l.index(),
            Self::TurbineValve => 17,
            Self::GeneratorOutput => 18,
            Self::CondenserPressure => 19,
            Self::CoreExitTemperature => 20,
            Self::ShutdownRodPosition => 21,
        }
    }
    /// Unit, minimum, maximum and resolution. Flow is per loop in kg/s.
    pub fn spec(self) -> Instrument {
        let (unit, min, max, resolution) = match self {
            Self::HotLeg(_) | Self::ColdLeg(_) | Self::CoreExitTemperature => {
                (Unit::Celsius, 0.0, 600.0, 0.1)
            }
            Self::PressurizerPressure => (Unit::Megapascal, 0.0, 25.0, 0.01),
            Self::SteamPressure => (Unit::Megapascal, 0.0, 12.0, 0.01),
            Self::CondenserPressure => (Unit::Kilopascal, 0.0, 100.0, 0.1),
            Self::SteamFlow(_) | Self::FeedFlow(_) => (Unit::KilogramsPerSecond, 0.0, 2000.0, 0.1),
            Self::GeneratorOutput => (Unit::Megawatt, 0.0, 1200.0, 0.1),
            Self::NeutronPower | Self::CoolantFlow(_) => (Unit::Percent, 0.0, 200.0, 0.1),
            _ => (Unit::Percent, 0.0, 100.0, 0.1),
        };
        Instrument {
            unit,
            min,
            max,
            resolution,
        }
    }
    fn temperature(self) -> bool {
        matches!(
            self,
            Self::HotLeg(_) | Self::ColdLeg(_) | Self::CoreExitTemperature
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Celsius,
    Megapascal,
    Kilopascal,
    KilogramsPerSecond,
    Megawatt,
    Percent,
}
impl Unit {
    pub const MAX_JSON_BYTES: usize = 22;
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Instrument {
    pub unit: Unit,
    pub min: f64,
    pub max: f64,
    pub resolution: f64,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reading {
    pub value: f64,
    pub sampled_at_ms: u64,
}
impl Reading {
    pub const MAX_JSON_BYTES: usize = 72;
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    pub sensor: Sensor,
    pub reading: Reading,
    pub fault: Option<SensorFault>,
}
impl Channel {
    pub const MAX_JSON_BYTES: usize = 158;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Telemetry {
    pub quiet: bool,
    pub heartbeat: u16,
    pub last_sample_ms: u64,
}
impl Telemetry {
    pub const MAX_JSON_BYTES: usize = 71;
}

pub(crate) fn round(value: f64, resolution: f64) -> f64 {
    let scaled = value / resolution;
    let integer = if scaled < 0.0 {
        (scaled - 0.5) as i64
    } else {
        (scaled + 0.5) as i64
    };
    // Division gives the canonical decimal's nearest binary representation.
    integer as f64 / (1.0 / resolution)
}

#[derive(Clone, Debug)]
pub(crate) struct Instruments {
    pub readings: [Reading; SENSOR_COUNT],
    lag: [f64; SENSOR_COUNT],
    random: u64,
    pub telemetry: Telemetry,
    pub status: ReportedStatus,
}
impl Instruments {
    pub fn new(seed: u64, values: [f64; SENSOR_COUNT], status: ReportedStatus) -> Self {
        Self {
            readings: std::array::from_fn(|i| Reading {
                value: round(values[i], Sensor::ALL[i].spec().resolution),
                sampled_at_ms: 0,
            }),
            status,
            lag: values,
            random: seed,
            telemetry: Telemetry {
                quiet: false,
                heartbeat: (seed ^ seed.rotate_right(17) ^ 0xa7c5) as u16,
                last_sample_ms: 0,
            },
        }
    }
    fn noise(&mut self) -> f64 {
        self.random = self.random.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.random;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        ((z >> 11) as f64 / 9007199254740992.0 - 0.5) * 1.2
    }
    pub fn step(
        &mut self,
        at_ms: u64,
        dt: f64,
        values: [f64; SENSOR_COUNT],
        status: ReportedStatus,
        faults: &Faults,
    ) {
        for sensor in Sensor::ALL {
            let i = sensor.index();
            if sensor.temperature() {
                self.lag[i] += dt * (values[i] - self.lag[i]) / 3.0;
            } else {
                self.lag[i] = values[i];
            }
        }
        self.telemetry.quiet = faults.telemetry_quiet;
        if !at_ms.is_multiple_of(SAMPLE_MS) || faults.telemetry_quiet {
            return;
        }
        self.status = status;
        self.telemetry.heartbeat = self.telemetry.heartbeat.wrapping_add(1);
        self.telemetry.last_sample_ms = at_ms;
        for sensor in Sensor::ALL {
            let i = sensor.index();
            let spec = sensor.spec();
            let noise = self.noise() * spec.resolution;
            let value = match faults.sensors[i] {
                Some(SensorFault::Quiet) => continue,
                Some(SensorFault::Stuck { value }) => f64::from(value) * spec.resolution,
                Some(SensorFault::Bias { delta }) => {
                    self.lag[i] + f64::from(delta) * spec.resolution + noise
                }
                None => self.lag[i] + noise,
            };
            self.readings[i] = Reading {
                value: round(value.clamp(spec.min, spec.max), spec.resolution),
                sampled_at_ms: at_ms,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Plant};

    #[test]
    fn shutdown_rods_sample_without_lag_and_obey_faults() {
        let status = Plant::new(Config::default()).snapshot().reported_status;
        let mut values = [0.0; SENSOR_COUNT];
        let i = Sensor::ShutdownRodPosition.index();
        let mut instruments = Instruments::new(0, values, status);
        let mut faults = Faults::default();
        values[i] = 75.0;
        instruments.step(200, 0.05, values, status, &faults);
        assert_eq!(instruments.readings[i].value, 0.0);
        instruments.step(250, 0.05, values, status, &faults);
        assert!((instruments.readings[i].value - 75.0).abs() <= 0.1);
        assert_eq!(instruments.readings[i].sampled_at_ms, 250);
        faults.sensors[i] = Some(SensorFault::Stuck { value: 321 });
        instruments.step(500, 0.05, values, status, &faults);
        assert_eq!(instruments.readings[i].value, 32.1);
        faults.sensors[i] = Some(SensorFault::Quiet);
        let held = instruments.readings[i];
        instruments.step(750, 0.05, values, status, &faults);
        assert_eq!(instruments.readings[i], held);
        faults.sensors[i] = None;
        faults.telemetry_quiet = true;
        instruments.step(1000, 0.05, values, status, &faults);
        assert_eq!(instruments.readings[i], held);
        faults.telemetry_quiet = false;
        instruments.step(1250, 0.05, values, status, &faults);
        assert!((instruments.readings[i].value - 75.0).abs() <= 0.1);
        assert_eq!(instruments.readings[i].sampled_at_ms, 1250);
    }
}
