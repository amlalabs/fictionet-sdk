//! Stylized: control room steam and radiation consequences, without transport physics.
use crate::{
    snapshot::{Regime, Severe, Stylized},
    stages::{Stage, StageLog},
};

/// Stylized: control room steam relaxation time in seconds.
const ROOM_SECONDS: f64 = 30.0;
/// Stylized: control room steam index at loss of habitability.
const UNINHABITABLE: f64 = 0.9;
/// Stylized: turbine hall steam density for full room steam, in kg/m3.
const HALL_KG_M3: f64 = 0.6;
/// Stylized: containment pressure where building leakage starts, in kPa.
const LEAK_START_KPA: f64 = 200.0;
/// Stylized: pressure rise for the full leakage contribution, in kPa.
const LEAK_SPAN_KPA: f64 = 400.0;
/// Stylized: full leakage contribution to the steam index.
const LEAK_SHARE: f64 = 0.5;
/// Stylized: cladding release rise time in milliseconds.
const RELEASE_MS: f64 = 600_000.0;
/// Stylized: cladding release fraction.
const CLADDING_SHARE: f64 = 0.05;
/// Stylized: melted fuel release fraction.
const MELT_SHARE: f64 = 0.4;
/// Stylized: ablation release fraction at three meters.
const ABLATION_SHARE: f64 = 0.1;
/// Stylized: ablation depth for full release contribution, in meters.
const ABLATION_M: f64 = 3.0;
/// Stylized: release reach before the primary opens to containment.
const CLOSED_REACH: f64 = 0.02;
/// Stylized: background dose rate in Sv/h.
const BACKGROUND_SV_H: f64 = 0.001;
/// Stylized: dose rate per release fraction in Sv/h.
const RELEASE_SV_H: f64 = 300.0;
/// Stylized: maximum dose rate in Sv/h.
const MAX_SV_H: f64 = 655.0;

/// Stylized: carried room steam and projected release and radiation values.
#[derive(Clone, Debug)]
pub(crate) struct StylizedState {
    /// Stylized: current consequences for the snapshot.
    pub values: Stylized,
}

/// Stylized: update the room index and radiation from the accident state.
impl StylizedState {
    /// Stylized: initial clear room and background radiation.
    pub fn new() -> Self {
        Self {
            values: Stylized {
                control_room_steam: 0.0,
                release_fraction: 0.0,
                containment_dose_sv_h: BACKGROUND_SV_H,
            },
        }
    }

    /// Stylized: return the habitability trigger at its first possible step.
    pub fn step(
        &mut self,
        severe: &Severe,
        stages: &StageLog,
        at_ms: u64,
        dt: f64,
    ) -> Option<Stage> {
        let hall = (severe.turbine_hall.steam_kg_m3 / HALL_KG_M3).clamp(0.0, 1.0);
        let leak =
            ((severe.containment.pressure_kpa - LEAK_START_KPA) / LEAK_SPAN_KPA).clamp(0.0, 1.0);
        let target = if severe.containment.failure.is_some() {
            1.0
        } else {
            (hall + LEAK_SHARE * leak).min(1.0)
        };
        let v = &mut self.values;
        v.control_room_steam += dt * (target - v.control_room_steam) / ROOM_SECONDS;
        let cladding = stages.times[Stage::CladdingFailure.index()]
            .map_or(0.0, |at| ((at_ms - at) as f64 / RELEASE_MS).min(1.0));
        v.release_fraction = CLADDING_SHARE * cladding
            + MELT_SHARE * severe.melted_percent / 100.0
            + ABLATION_SHARE * (severe.cavity.ablation_m / ABLATION_M).min(1.0);
        let reach = if severe.relief_tank.disk_ruptured
            || severe.regime == Regime::Breached
            || severe.containment.failure.is_some()
        {
            1.0
        } else {
            CLOSED_REACH
        };
        v.containment_dose_sv_h =
            (BACKGROUND_SV_H + RELEASE_SV_H * v.release_fraction * reach).min(MAX_SV_H);
        (v.control_room_steam >= UNINHABITABLE).then_some(Stage::ControlRoomUninhabitable)
    }
}
