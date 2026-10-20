//! Steam mass and temperature in the turbine hall.
use crate::snapshot::TurbineHall;

/// Rule: turbine hall volume in cubic meters.
const HALL_VOLUME_M3: f64 = 60_000.0;
/// Rule: hall venting time constant in seconds.
const VENT_SECONDS: f64 = 300.0;
/// Rule: steam density in kg/m3 at the hall stage threshold.
const STAGE_DENSITY_KG_M3: f64 = 0.3;
/// Rule: steam density in kg/m3 at the hall temperature ceiling of 100 C.
const HOT_DENSITY_KG_M3: f64 = 0.6;
/// Rule: hall temperature without steam, in C.
const AMBIENT_C: f64 = 30.0;
/// Rule: maximum steam-driven hall temperature rise, in C.
const STEAM_RISE_C: f64 = 70.0;

#[derive(Clone, Debug, Default)]
pub(crate) struct Hall {
    steam_kg: f64,
}
impl Hall {
    pub fn step(&mut self, inflow_kg_s: f64, dt: f64) -> bool {
        self.steam_kg += dt * (inflow_kg_s - self.steam_kg / VENT_SECONDS);
        self.steam_kg / HALL_VOLUME_M3 >= STAGE_DENSITY_KG_M3
    }
    pub fn snapshot(&self) -> TurbineHall {
        let c = self.steam_kg / HALL_VOLUME_M3;
        TurbineHall {
            steam_kg_m3: c,
            temperature_c: AMBIENT_C + STEAM_RISE_C * (c / HOT_DENSITY_KG_M3).clamp(0.0, 1.0),
        }
    }
}
