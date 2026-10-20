//! Rounded saturation properties in MPa, C, and kJ/kg, with linear interpolation.
//!
//! These coarse educational values follow IAPWS-IF97 saturation properties;
//! this is not an implementation of IF97. Endpoints clamp at 0.1 and 18 MPa.
//! Added primary rows use IF97 region 4 temperatures and saturated enthalpies
//! from regions 1/2 below 16.5292 MPa and region 3 above it. Values are rounded
//! to 0.01 C and 0.1 kJ/kg. See the [IAPWS release](https://iapws.org/technical-guidance/release/IF97-Rev).
//! Secondary pressure still clamps at 0.1–8.5 MPa in the plant. Feedwater at
//! about 225 C uses 970 kJ/kg; auxiliary water at 30 C uses 126 kJ/kg.

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Saturation {
    pub temperature_c: f64,
    pub liquid_kj_kg: f64,
    pub vapor_kj_kg: f64,
}

// Pressure, temperature, saturated liquid enthalpy, saturated vapor enthalpy.
const TABLE: [[f64; 4]; 14] = [
    [0.1, 99.61, 417.4, 2674.9],
    [1.0, 179.88, 762.7, 2777.1],
    [3.0, 233.86, 1008.4, 2803.3],
    [5.0, 263.94, 1154.5, 2794.2],
    [6.9, 284.83, 1262.0, 2774.0],
    [7.0, 285.83, 1267.0, 2772.6],
    [8.0, 295.01, 1317.1, 2758.0],
    [10.0, 311.0, 1407.9, 2725.5],
    [12.0, 324.68, 1491.3, 2685.6],
    [14.0, 336.67, 1570.9, 2638.1],
    [15.5, 344.79, 1629.9, 2596.2],
    [16.0, 347.36, 1649.7, 2580.8],
    [17.0, 352.29, 1690.0, 2547.4],
    [18.0, 356.99, 1732.0, 2509.5],
];
pub const FEED_ENTHALPY: f64 = 970.0;
pub const AUX_ENTHALPY: f64 = 126.0;

pub fn saturation(pressure_mpa: f64) -> Saturation {
    let p = pressure_mpa.clamp(TABLE[0][0], TABLE[TABLE.len() - 1][0]);
    for pair in TABLE.windows(2) {
        let [a, b] = [pair[0], pair[1]];
        if p <= b[0] {
            let f = (p - a[0]) / (b[0] - a[0]);
            return Saturation {
                temperature_c: a[1] + f * (b[1] - a[1]),
                liquid_kj_kg: a[2] + f * (b[2] - a[2]),
                vapor_kj_kg: a[3] + f * (b[3] - a[3]),
            };
        }
    }
    unreachable!("pressure is bounded by the table")
}

/// Saturation pressure in MPa, interpolated by temperature in C.
pub fn saturation_pressure(t_c: f64) -> f64 {
    let t = t_c.clamp(TABLE[0][1], TABLE[TABLE.len() - 1][1]);
    for pair in TABLE.windows(2) {
        let [a, b] = [pair[0], pair[1]];
        if t <= b[1] {
            return a[0] + (t - a[1]) / (b[1] - a[1]) * (b[0] - a[0]);
        }
    }
    unreachable!("temperature is bounded by the table")
}

/// Saturated temperature in C, pressure in kPa and vapor density in kg/m3.
const ATMOSPHERE: [[f64; 3]; 9] = [
    [40.0, 7.38, 0.0512],
    [60.0, 19.95, 0.1302],
    [80.0, 47.41, 0.2937],
    [100.0, 101.42, 0.5982],
    [120.0, 198.67, 1.1219],
    [140.0, 361.53, 1.9665],
    [160.0, 618.23, 3.2594],
    [180.0, 1002.8, 5.1597],
    [200.0, 1554.9, 7.8603],
];
/// Steam temperature in C and partial pressure in kPa at a density in kg/m3.
pub fn atmosphere(steam_kg_m3: f64) -> (f64, f64) {
    if steam_kg_m3 <= ATMOSPHERE[0][2] {
        return (40.0, steam_kg_m3 * 144.5);
    }
    for pair in ATMOSPHERE.windows(2) {
        let [a, b] = [pair[0], pair[1]];
        if steam_kg_m3 <= b[2] {
            let f = (steam_kg_m3 - a[2]) / (b[2] - a[2]);
            return (a[0] + f * (b[0] - a[0]), a[1] + f * (b[1] - a[1]));
        }
    }
    (200.0, 1554.9)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_saturation_rows_and_interpolation() {
        for row in TABLE {
            assert!((saturation_pressure(row[1]) - row[0]).abs() < 0.001);
            assert!((saturation_pressure(saturation(row[0]).temperature_c) - row[0]).abs() < 0.001);
        }
        for pair in TABLE.windows(2) {
            assert!(
                (saturation_pressure((pair[0][1] + pair[1][1]) / 2.0)
                    - (pair[0][0] + pair[1][0]) / 2.0)
                    .abs()
                    < 0.001
            );
        }
        assert_eq!(saturation_pressure(0.0), 0.1);
        assert_eq!(saturation_pressure(400.0), 18.0);
    }

    #[test]
    fn atmosphere_rows_low_density_and_clamp() {
        assert_eq!(atmosphere(0.5982), (100.0, 101.42));
        assert_eq!(atmosphere(0.03), (40.0, 4.335));
        assert_eq!(atmosphere(10.0), (200.0, 1554.9));
        assert_eq!(atmosphere(0.0512), (40.0, 0.0512 * 144.5));
        for row in &ATMOSPHERE[1..] {
            let (t, p) = atmosphere(row[2]);
            assert!((t - row[0]).abs() < 1e-10);
            assert!((p - row[1]).abs() < 1e-10);
        }
    }
}
