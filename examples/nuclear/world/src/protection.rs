//! Representative trip thresholds, not a plant protection specification.
//! Trips use true channels: 109% neutron power, 17/13 MPa pressurizer pressure,
//! 70% loop flow above 20% power, 20% steam generator level, 343 C hot leg,
//! and turbine trip above 20% power. Manual trip always works.
//! The condenser trips the turbine at 15 kPa even with reactor protection off.
//! First cause is latched. Reset evaluates present conditions, including the
//! turbine-power interlock, but not the reactor's own latched trip status.
//!
//! Alarms use reported values and equipment status. A lying temperature can
//! hide its alarm; there is deliberately no stale-data alarm here. Analog
//! alarms clear across a deadband: 0.2 MPa, 1 C, 2 percentage points, 5 kg/s,
//! or 1 kPa. Acknowledgment persists until the condition clears.
//!
//! Alarm limits are representative: pressurizer pressure 16.2/14.5 MPa;
//! pressurizer level 70/30%; hot leg 335 C; SG level 35/75%; feed deficit
//! 30 kg/s; coolant flow 80%; condenser 12 kPa; neutron power 105%.
//! Subcooling margin uses reported pressure and core exit temperature. It alarms
//! below 15 C and clears at 16 C. Equipment alarms use sampled reported status
//! for stopped pumps, open relief and latched trips.
use crate::{
    command::Loop,
    sensors::{Reading, SENSOR_COUNT, Sensor},
    snapshot::ReportedStatus,
    steam,
};
use serde::{Deserialize, Serialize};

pub const HIGH_HOT_LEG_C: f64 = 343.0;
pub const LOW_LOW_LEVEL: f64 = 20.0;
pub const LOW_VACUUM_KPA: f64 = 15.0;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripCause {
    Manual,
    NeutronPowerHigh,
    PressurizerPressureHigh,
    PressurizerPressureLow,
    CoolantFlowLow(Loop),
    SteamGeneratorLevelLow(Loop),
    HotLegTemperatureHigh(Loop),
    TurbineTrip,
}
impl TripCause {
    pub const MAX_JSON_BYTES: usize = 33;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trip {
    pub cause: TripCause,
    pub at_ms: u64,
}
impl Trip {
    pub const MAX_JSON_BYTES: usize = 72;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alarm {
    PressurizerPressureHigh,
    PressurizerPressureLow,
    PressurizerLevelHigh,
    PressurizerLevelLow,
    HotLegTemperatureHigh(Loop),
    SteamGeneratorLevelLow(Loop),
    SteamGeneratorLevelHigh(Loop),
    FeedFlowLow(Loop),
    CoolantFlowLow(Loop),
    CondenserVacuumLow,
    FeedPumpTripped,
    CoolantPumpTripped,
    ReliefValveOpen,
    ReactorTripped,
    TurbineTripped,
    NeutronPowerHigh,
    SubcoolingMarginLow,
}
pub const ALARM_COUNT: usize = 22;
impl Alarm {
    pub const MAX_JSON_BYTES: usize = 34;
    pub const ALL: [Self; ALARM_COUNT] = [
        Self::PressurizerPressureHigh,
        Self::PressurizerPressureLow,
        Self::PressurizerLevelHigh,
        Self::PressurizerLevelLow,
        Self::HotLegTemperatureHigh(Loop::A),
        Self::HotLegTemperatureHigh(Loop::B),
        Self::SteamGeneratorLevelLow(Loop::A),
        Self::SteamGeneratorLevelLow(Loop::B),
        Self::SteamGeneratorLevelHigh(Loop::A),
        Self::SteamGeneratorLevelHigh(Loop::B),
        Self::FeedFlowLow(Loop::A),
        Self::FeedFlowLow(Loop::B),
        Self::CoolantFlowLow(Loop::A),
        Self::CoolantFlowLow(Loop::B),
        Self::CondenserVacuumLow,
        Self::FeedPumpTripped,
        Self::CoolantPumpTripped,
        Self::ReliefValveOpen,
        Self::ReactorTripped,
        Self::TurbineTripped,
        Self::NeutronPowerHigh,
        Self::SubcoolingMarginLow,
    ];
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|a| *a == self).unwrap()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmState {
    Normal,
    Active,
    Acknowledged,
}
impl AlarmState {
    pub const MAX_JSON_BYTES: usize = 14;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlarmEntry {
    pub alarm: Alarm,
    pub state: AlarmState,
}
impl AlarmEntry {
    pub const MAX_JSON_BYTES: usize = 67;
}

pub(crate) struct ProtectionInputs {
    pub power: f64,
    pub pressure: f64,
    pub flow: [f64; 2],
    pub level: [f64; 2],
    pub hot: [f64; 2],
    pub turbine_trip: bool,
}
impl ProtectionInputs {
    pub fn cause(&self) -> Option<TripCause> {
        if self.power > 109.0 {
            return Some(TripCause::NeutronPowerHigh);
        }
        if self.pressure > 17.0 {
            return Some(TripCause::PressurizerPressureHigh);
        }
        if self.pressure < 13.0 {
            return Some(TripCause::PressurizerPressureLow);
        }
        for l in Loop::ALL {
            let i = l.index();
            if self.power > 20.0 && self.flow[i] < 70.0 {
                return Some(TripCause::CoolantFlowLow(l));
            }
            if self.level[i] < LOW_LOW_LEVEL {
                return Some(TripCause::SteamGeneratorLevelLow(l));
            }
            if self.hot[i] > HIGH_HOT_LEG_C {
                return Some(TripCause::HotLegTemperatureHigh(l));
            }
        }
        if self.turbine_trip && self.power > 20.0 {
            return Some(TripCause::TurbineTrip);
        }
        None
    }
}

pub(crate) fn update_alarms(
    states: &mut [AlarmState; ALARM_COUNT],
    readings: &[Reading; SENSOR_COUNT],
    status: ReportedStatus,
) {
    let read = |s: Sensor| readings[s.index()].value;
    for alarm in Alarm::ALL {
        let state = &mut states[alarm.index()];
        let latched = *state != AlarmState::Normal;
        let high = |value: f64, threshold: f64, deadband: f64| {
            value > threshold - if latched { deadband } else { 0.0 }
        };
        let low = |value: f64, threshold: f64, deadband: f64| {
            value < threshold + if latched { deadband } else { 0.0 }
        };
        let active = match alarm {
            Alarm::PressurizerPressureHigh => high(read(Sensor::PressurizerPressure), 16.2, 0.2),
            Alarm::PressurizerPressureLow => low(read(Sensor::PressurizerPressure), 14.5, 0.2),
            Alarm::PressurizerLevelHigh => high(read(Sensor::PressurizerLevel), 70.0, 2.0),
            Alarm::PressurizerLevelLow => low(read(Sensor::PressurizerLevel), 30.0, 2.0),
            Alarm::HotLegTemperatureHigh(l) => high(read(Sensor::HotLeg(l)), 335.0, 1.0),
            Alarm::SteamGeneratorLevelLow(l) => {
                low(read(Sensor::SteamGeneratorLevel(l)), 35.0, 2.0)
            }
            Alarm::SteamGeneratorLevelHigh(l) => {
                high(read(Sensor::SteamGeneratorLevel(l)), 75.0, 2.0)
            }
            Alarm::FeedFlowLow(l) => low(
                read(Sensor::FeedFlow(l)) - read(Sensor::SteamFlow(l)),
                -30.0,
                5.0,
            ),
            Alarm::CoolantFlowLow(l) => low(read(Sensor::CoolantFlow(l)), 80.0, 2.0),
            Alarm::CondenserVacuumLow => high(read(Sensor::CondenserPressure), 12.0, 1.0),
            Alarm::FeedPumpTripped => status.feed_pumps_running.iter().any(|p| !p),
            Alarm::CoolantPumpTripped => status.coolant_pumps_running.iter().any(|p| !p),
            Alarm::ReliefValveOpen => status.pressurizer_relief_open || status.steam_relief_open,
            Alarm::ReactorTripped => status.reactor_tripped,
            Alarm::TurbineTripped => status.turbine_tripped,
            Alarm::SubcoolingMarginLow => low(
                steam::saturation(read(Sensor::PressurizerPressure)).temperature_c
                    - read(Sensor::CoreExitTemperature),
                15.0,
                1.0,
            ),
            Alarm::NeutronPowerHigh => high(read(Sensor::NeutronPower), 105.0, 2.0),
        };
        if !active {
            *state = AlarmState::Normal;
        } else if !latched {
            *state = AlarmState::Active;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal() -> ProtectionInputs {
        ProtectionInputs {
            power: 100.0,
            pressure: 15.5,
            flow: [100.0; 2],
            level: [50.0; 2],
            hot: [325.0; 2],
            turbine_trip: false,
        }
    }

    #[test]
    fn trip_channels_and_low_power_interlocks() {
        assert_eq!(normal().cause(), None);
        let mut p = normal();
        p.power = 110.0;
        assert_eq!(p.cause(), Some(TripCause::NeutronPowerHigh));
        let mut p = normal();
        p.pressure = 17.1;
        assert_eq!(p.cause(), Some(TripCause::PressurizerPressureHigh));
        p.pressure = 12.9;
        assert_eq!(p.cause(), Some(TripCause::PressurizerPressureLow));
        for l in Loop::ALL {
            let mut p = normal();
            p.flow[l.index()] = 69.0;
            assert_eq!(p.cause(), Some(TripCause::CoolantFlowLow(l)));
            p.power = 19.0;
            assert_eq!(p.cause(), None);
            let mut p = normal();
            p.level[l.index()] = 19.0;
            assert_eq!(p.cause(), Some(TripCause::SteamGeneratorLevelLow(l)));
            let mut p = normal();
            p.hot[l.index()] = 344.0;
            assert_eq!(p.cause(), Some(TripCause::HotLegTemperatureHigh(l)));
        }
        let mut p = normal();
        p.turbine_trip = true;
        assert_eq!(p.cause(), Some(TripCause::TurbineTrip));
        p.power = 19.0;
        assert_eq!(p.cause(), None);
    }
}
