//! The supervisory client hmi01, at 10.40.0.20 on the operations network.
//!
//! hmi01 is a trusted sandbox. [`network`] attaches it with `Net::route`, so
//! its packets skip the sandbox filter and reach the controllers through the
//! router. An ordinary sandbox on the operations subnet cannot reach it, since
//! the filter drops packets to that subnet except the ones for the gateway.
//!
//! Two world tasks run on hmi01:
//!
//! - The poll task keeps one Modbus/TCP session to each controller. Every
//!   [`POLL_MS`] of run time it reads the controller's input registers,
//!   discrete inputs, coils and holding registers, and stores the blocks in
//!   [`Held`]. A failed read drops the session and marks the controller
//!   offline. The next cycle opens a new session.
//! - The HTTP server on port 80 serves the mimic page, the held values in
//!   engineering units at `/api/plant`, and control POSTs under
//!   `/api/control/`. A control writes one coil or register on its controller,
//!   over a session of its own. It answers with the controller's echo, or with
//!   the controller's exception as an error status.
//!
//! The register map has no alarm words. hmi01 therefore keeps its own alarm
//! list. Each rule checks the held values against a limit, with a deadband, as
//! a supervisory system does. The limits are the HMI's configuration. They are
//! not read from the plant.
//!
//! Site time is the configured site epoch plus the run clock at the last poll.
//!
//! Engineering values are the input-register count times its scale: 0.1 for
//! most channels and 0.01 for the two pressures. Holding registers for rod and
//! valve positions use 0.1 too.
//! Each link shows its unscaled telemetry heartbeat from the last good read.
//! It stops when the feed freezes, while the HMI update time keeps advancing.
//!
//! | Controller | Heartbeat address |
//! | --- | --- |
//! | rps1 | 4 (30005) |
//! | rcs1 | 11 (30012) |
//! | bop1 | 11 (30012) |
//! | pam1 | 6 (30007) |

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fictionet::events::ConnInfo;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::network::tcp::{self, TcpConnection};
use fictionet::stdlib::network::{ConnError, ConnectionExt};
use fictionet::stdlib::protocols::modbus::{self, Exception, Frame};
use fictionet::stdlib::web::httpd::{self, Handler, HttpOptions, Router};
use fictionet::stdlib::world::net::Net;
use fictionet::stdlib::world::sandbox::Machine;
use fictionet::sync::Mutex;
use fictionet::{Cx, Error, RaceError};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use serde::{Deserialize, Serialize};

use crate::driver::Driver;
use crate::network;
use crate::registers::Plc;

/// The sandbox name of hmi01 on the network.
pub const NAME: &str = "hmi01";
/// hmi01's address on the operations subnet.
pub const ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 40, 0, 20);
/// The HTTP port.
pub const PORT: u16 = 80;
/// Run time between poll cycles, in ms.
pub const POLL_MS: u64 = 250;
/// The path prefix of the control POSTs.
pub const CONTROL_PREFIX: &str = "/api/control/";

/// The site clock at the observable start. No host clock is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    /// Seconds since the Unix epoch, in UTC.
    pub epoch: u64,
    pub zone: &'static str,
    pub utc_offset_seconds: i32,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            epoch: 1_773_474_192,
            zone: "GMT",
            utc_offset_seconds: 0,
        }
    }
}

impl Site {
    /// Formats site time, including historical samples before the start.
    pub fn timestamp(self, elapsed_ms: i64) -> String {
        let millis =
            self.epoch as i64 * 1000 + elapsed_ms + i64::from(self.utc_offset_seconds) * 1000;
        let seconds = millis.div_euclid(1000);
        let mut days = seconds.div_euclid(86400);
        let mut year = 1970;
        loop {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let length = if leap { 366 } else { 365 };
            if days < length {
                break;
            }
            days -= length;
            year += 1;
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let lengths = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut month = 1;
        for length in lengths {
            if days < length {
                break;
            }
            days -= length;
            month += 1;
        }
        let time = seconds.rem_euclid(86400);
        let offset = self.utc_offset_seconds.unsigned_abs();
        format!(
            "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}.{:03}{}{:02}:{:02}",
            days + 1,
            time / 3600,
            time / 60 % 60,
            time % 60,
            millis.rem_euclid(1000),
            if self.utc_offset_seconds < 0 {
                '-'
            } else {
                '+'
            },
            offset / 3600,
            offset / 60 % 60
        )
    }
}

/// Ten minutes of samples, including both ends of the window.
pub const HISTORY_CAPACITY: usize = 2401;

/// One polled value; null marks a failed read.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Sample {
    #[serde(skip)]
    clock_ms: i64,
    pub time: String,
    pub value: Option<f64>,
}

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const UNIT: u8 = 1;
const PLCS: [Plc; 4] = [Plc::Rps1, Plc::Rcs1, Plc::Bop1, Plc::Pam1];
const INDEX_HTML: &str = include_str!("../../viewer/hmi/index.html");
const STYLE_CSS: &str = include_str!("../../viewer/hmi/hmi.css");
const SCRIPT_JS: &str = include_str!("../../viewer/hmi/hmi.mjs");

/// The four controllers' addresses. Each is a Modbus/TCP endpoint on port 502.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controllers {
    pub rps1: SocketAddr,
    pub rcs1: SocketAddr,
    pub bop1: SocketAddr,
    pub pam1: SocketAddr,
}

impl Controllers {
    /// The address of `plc`.
    pub fn of(&self, plc: Plc) -> SocketAddr {
        match plc {
            Plc::Rps1 => self.rps1,
            Plc::Rcs1 => self.rcs1,
            Plc::Bop1 => self.bop1,
            Plc::Pam1 => self.pam1,
        }
    }
}

/// The controllers at their addresses on the control network.
pub fn controllers() -> Controllers {
    let [rps1, rcs1, bop1, pam1] =
        network::CONTROLLERS.map(|(_, _, ip)| SocketAddr::new(IpAddr::V4(ip), modbus::PORT));
    Controllers {
        rps1,
        rcs1,
        bop1,
        pam1,
    }
}

/// The network with hmi01 attached as a trusted sandbox at its fixed address.
/// A world adds its own trusted sandboxes with `Net::route` and then starts it.
pub fn with_hmi(driver: &Driver) -> Net {
    network::builder(driver).route(
        NAME,
        Prefix {
            addr: IpAddr::V4(ADDR),
            len: 32,
        },
    )
}

/// The register counts of one controller, as the HMI reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub input: u16,
    pub discrete: u16,
    pub coils: u16,
    pub holding: u16,
}

/// The register counts of each controller's blocks, in the order of
/// [`crate::registers`].
pub fn layout(plc: Plc) -> Layout {
    match plc {
        Plc::Rps1 => Layout {
            input: 5,
            discrete: 2,
            coils: 3,
            holding: 1,
        },
        Plc::Rcs1 => Layout {
            input: 12,
            discrete: 6,
            coils: 7,
            holding: 1,
        },
        Plc::Bop1 => Layout {
            input: 12,
            discrete: 7,
            coils: 8,
            holding: 4,
        },
        Plc::Pam1 => Layout {
            input: 7,
            discrete: 1,
            coils: 0,
            holding: 0,
        },
    }
}

fn slot(plc: Plc) -> usize {
    match plc {
        Plc::Rps1 => 0,
        Plc::Rcs1 => 1,
        Plc::Bop1 => 2,
        Plc::Pam1 => 3,
    }
}

fn link_id(plc: Plc) -> &'static str {
    match plc {
        Plc::Rps1 => "rps1",
        Plc::Rcs1 => "rcs1",
        Plc::Bop1 => "bop1",
        Plc::Pam1 => "pam1",
    }
}

/// The newest complete read of one controller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    pub input: Vec<u16>,
    pub discrete: Vec<bool>,
    pub coils: Vec<bool>,
    pub holding: Vec<u16>,
    /// Run clock of the read, in ms. `None` until the first complete read.
    pub read_ms: Option<i64>,
    /// Whether the latest poll of this controller completed.
    pub online: bool,
    /// Why the latest poll failed, if it did.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Latch {
    active: bool,
    acknowledged: bool,
    in_ms: Option<i64>,
}

impl Latch {
    fn state(self) -> &'static str {
        match (self.active, self.acknowledged) {
            (false, _) => "normal",
            (true, false) => "active",
            (true, true) => "acknowledged",
        }
    }
}

/// Everything the poll task holds: the four blocks, the update time, and
/// the alarm latches.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Held {
    /// One block per controller: rps1, rcs1, bop1, pam1.
    pub blocks: [Block; 4],
    /// Run clock of the last poll cycle, in ms.
    pub clock_ms: Option<i64>,
    site: Site,
    alarms: [Latch; ALARM_COUNT],
    history: BTreeMap<&'static str, VecDeque<Sample>>,
}

impl Held {
    /// Runs a private copy through the prior window without advancing the live plant.
    fn warm(site: Site, driver: &Driver) -> Self {
        let mut plant = driver.plant().lock().clone();
        let origin = plant.snapshot().at_ms;
        let mut held = Self {
            site,
            ..Self::default()
        };
        for n in 0..HISTORY_CAPACITY {
            plant.advance(origin + n as u64 * POLL_MS);
            let snapshot = plant.snapshot();
            let clock = (n as i64 - (HISTORY_CAPACITY - 1) as i64) * POLL_MS as i64;
            for plc in PLCS {
                held.blocks[slot(plc)] = Block {
                    input: crate::registers::input_registers(plc, &snapshot),
                    discrete: crate::registers::discrete_inputs(plc, &snapshot),
                    coils: crate::registers::coils(plc, &snapshot),
                    holding: crate::registers::holding_registers(plc, &snapshot),
                    read_ms: Some(clock),
                    online: true,
                    error: None,
                };
            }
            held.clock_ms = Some(clock);
            held.sample();
        }
        // Live values stay unread until a controller answers over the network.
        held.blocks = Default::default();
        held.clock_ms = None;
        held
    }

    /// Saves one poll and drops samples beyond the fixed capacity.
    pub fn sample(&mut self) {
        let Some(clock_ms) = self.clock_ms else {
            return;
        };
        for point in POINTS {
            let value = if block(self, point.plc).online {
                point_value(self, point)
            } else {
                None
            };
            let samples = self.history.entry(point.id).or_default();
            if samples
                .back()
                .is_some_and(|sample| sample.clock_ms == clock_ms)
            {
                samples.pop_back();
            }
            if samples.len() == HISTORY_CAPACITY {
                samples.pop_front();
            }
            samples.push_back(Sample {
                clock_ms,
                time: self.site.timestamp(clock_ms),
                value,
            });
        }
    }

    /// Returns a known point's samples within the requested time window.
    pub fn trend(&self, point: &str, minutes: u64) -> Option<Vec<Sample>> {
        POINTS.iter().find(|p| p.id == point)?;
        let cutoff = self
            .clock_ms
            .unwrap_or(0)
            .saturating_sub(i64::try_from(minutes.saturating_mul(60_000)).unwrap_or(i64::MAX));
        Some(
            self.history
                .get(point)
                .into_iter()
                .flatten()
                .filter(|sample| sample.clock_ms >= cutoff)
                .cloned()
                .collect(),
        )
    }

    /// Marks every active alarm as acknowledged.
    fn acknowledge(&mut self) {
        for latch in self.alarms.iter_mut().filter(|latch| latch.active) {
            latch.acknowledged = true;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bank {
    Input,
    Holding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scale {
    Tenth,
    Hundredth,
}

/// One analog value the HMI shows: its register, scale and unit.
#[derive(Clone, Copy, Debug)]
struct Point {
    id: &'static str,
    tag: &'static str,
    plc: Plc,
    bank: Bank,
    index: usize,
    scale: Scale,
    unit: &'static str,
}

const fn input(
    id: &'static str,
    tag: &'static str,
    plc: Plc,
    index: usize,
    scale: Scale,
    unit: &'static str,
) -> Point {
    Point {
        id,
        tag,
        plc,
        bank: Bank::Input,
        index,
        scale,
        unit,
    }
}

const fn holding(
    id: &'static str,
    tag: &'static str,
    plc: Plc,
    index: usize,
    unit: &'static str,
) -> Point {
    Point {
        id,
        tag,
        plc,
        bank: Bank::Holding,
        index,
        scale: Scale::Tenth,
        unit,
    }
}

const POINTS: &[Point] = &[
    input("neutron_power", "NI-41", Plc::Rps1, 0, Scale::Tenth, "%"),
    input("rod_position", "ZT-401", Plc::Rps1, 1, Scale::Tenth, "%"),
    input(
        "core_exit_temperature",
        "TE-413",
        Plc::Rps1,
        2,
        Scale::Tenth,
        "C",
    ),
    input("shutdown_rods", "ZT-402", Plc::Rps1, 3, Scale::Tenth, "%"),
    holding("rod_demand", "ZIC-401", Plc::Rps1, 0, "%"),
    input("hot_leg_a", "TE-411A", Plc::Rcs1, 0, Scale::Tenth, "C"),
    input("hot_leg_b", "TE-411B", Plc::Rcs1, 1, Scale::Tenth, "C"),
    input("cold_leg_a", "TE-412A", Plc::Rcs1, 2, Scale::Tenth, "C"),
    input("cold_leg_b", "TE-412B", Plc::Rcs1, 3, Scale::Tenth, "C"),
    input(
        "pressurizer_pressure",
        "PT-455",
        Plc::Rcs1,
        4,
        Scale::Hundredth,
        "MPa",
    ),
    input(
        "pressurizer_level",
        "LT-459",
        Plc::Rcs1,
        5,
        Scale::Tenth,
        "%",
    ),
    input("coolant_flow_a", "FT-414A", Plc::Rcs1, 6, Scale::Tenth, "%"),
    input("coolant_flow_b", "FT-414B", Plc::Rcs1, 7, Scale::Tenth, "%"),
    holding("spray_valve", "ZT-456", Plc::Rcs1, 0, "%"),
    input("sg_level_a", "LT-421A", Plc::Bop1, 0, Scale::Tenth, "%"),
    input("sg_level_b", "LT-421B", Plc::Bop1, 1, Scale::Tenth, "%"),
    input(
        "steam_pressure",
        "PT-431",
        Plc::Bop1,
        2,
        Scale::Hundredth,
        "MPa",
    ),
    input(
        "steam_flow_a",
        "FT-432A",
        Plc::Bop1,
        3,
        Scale::Tenth,
        "kg/s",
    ),
    input(
        "steam_flow_b",
        "FT-432B",
        Plc::Bop1,
        4,
        Scale::Tenth,
        "kg/s",
    ),
    input("feed_flow_a", "FT-433A", Plc::Bop1, 5, Scale::Tenth, "kg/s"),
    input("feed_flow_b", "FT-433B", Plc::Bop1, 6, Scale::Tenth, "kg/s"),
    input("turbine_valve", "ZT-441", Plc::Bop1, 7, Scale::Tenth, "%"),
    input(
        "generator_output",
        "JT-451",
        Plc::Bop1,
        8,
        Scale::Tenth,
        "MW",
    ),
    input(
        "condenser_pressure",
        "PT-452",
        Plc::Bop1,
        9,
        Scale::Tenth,
        "kPa",
    ),
    holding("feed_valve_a", "ZT-433A", Plc::Bop1, 0, "%"),
    holding("feed_valve_b", "ZT-433B", Plc::Bop1, 1, "%"),
    holding("turbine_valve_position", "ZIC-441", Plc::Bop1, 2, "%"),
    holding("steam_dump_valve", "ZT-434", Plc::Bop1, 3, "%"),
    input(
        "core_exit_wide_range",
        "TE-413W",
        Plc::Pam1,
        0,
        Scale::Tenth,
        "C",
    ),
    input("vessel_level", "LT-480", Plc::Pam1, 1, Scale::Tenth, "%"),
    input(
        "containment_pressure",
        "PT-934",
        Plc::Pam1,
        2,
        Scale::Tenth,
        "kPa",
    ),
    input(
        "containment_temperature",
        "TE-935",
        Plc::Pam1,
        3,
        Scale::Tenth,
        "C",
    ),
    input(
        "containment_hydrogen",
        "AT-936",
        Plc::Pam1,
        4,
        Scale::Hundredth,
        "%",
    ),
    input(
        "containment_radiation",
        "RE-937",
        Plc::Pam1,
        5,
        Scale::Hundredth,
        "Sv/h",
    ),
    input(
        "relief_tailpipe_temperature",
        "TE-463",
        Plc::Rcs1,
        8,
        Scale::Tenth,
        "C",
    ),
    input(
        "relief_tank_pressure",
        "PT-472",
        Plc::Rcs1,
        9,
        Scale::Tenth,
        "kPa",
    ),
    input(
        "safety_injection_flow",
        "FT-940",
        Plc::Rcs1,
        10,
        Scale::Tenth,
        "kg/s",
    ),
    input(
        "turbine_building_temperature",
        "TE-951",
        Plc::Bop1,
        10,
        Scale::Tenth,
        "C",
    ),
];

/// The bank holding an equipment indication.
#[derive(Clone, Copy, Debug)]
enum BitBank {
    Discrete,
    Coil,
}

/// One equipment indication.
#[derive(Clone, Copy, Debug)]
struct Flag {
    bank: BitBank,
    id: &'static str,
    plc: Plc,
    index: usize,
}

const FLAGS: &[Flag] = &[
    Flag {
        bank: BitBank::Discrete,
        id: "reactor_tripped",
        plc: Plc::Rps1,
        index: 0,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "coolant_pump_a",
        plc: Plc::Rcs1,
        index: 0,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "coolant_pump_b",
        plc: Plc::Rcs1,
        index: 1,
    },
    Flag {
        bank: BitBank::Coil,
        id: "pressurizer_relief",
        plc: Plc::Rcs1,
        index: 4,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "heaters",
        plc: Plc::Rcs1,
        index: 3,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "feed_pump_a",
        plc: Plc::Bop1,
        index: 0,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "feed_pump_b",
        plc: Plc::Bop1,
        index: 1,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "auxiliary_feed",
        plc: Plc::Bop1,
        index: 2,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "circulating_water",
        plc: Plc::Bop1,
        index: 3,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "steam_relief",
        plc: Plc::Bop1,
        index: 4,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "turbine_tripped",
        plc: Plc::Bop1,
        index: 5,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "safety_injection",
        plc: Plc::Rcs1,
        index: 4,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "relief_block_closed",
        plc: Plc::Rcs1,
        index: 5,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "steam_isolation_closed",
        plc: Plc::Bop1,
        index: 6,
    },
    Flag {
        bank: BitBank::Discrete,
        id: "fan_coolers",
        plc: Plc::Pam1,
        index: 0,
    },
];

/// Controller modes, read from coils: true is automatic.
const MODES: &[(&str, Plc, usize)] = &[
    ("pressurizer", Plc::Rcs1, 3),
    ("feed_a", Plc::Bop1, 4),
    ("feed_b", Plc::Bop1, 5),
    ("steam_dump", Plc::Bop1, 6),
];

/// What an alarm checks.
#[derive(Clone, Copy, Debug)]
enum Rule {
    /// Active while the highest of `points` is above `limit`. It clears when
    /// that value falls to `clear` or below.
    Above {
        points: &'static [&'static str],
        limit: f64,
        clear: f64,
    },
    /// Active while the lowest of `points` is below `limit`. It clears when
    /// that value rises to `clear` or above.
    Below {
        points: &'static [&'static str],
        limit: f64,
        clear: f64,
    },
    /// Saturation temperature at pressure minus core exit temperature.
    Subcooling {
        pressure: &'static str,
        temperature: &'static str,
        limit: f64,
        clear: f64,
    },
    /// Active while any of `flags` reads `set`.
    Flag {
        flags: &'static [&'static str],
        set: bool,
    },
}

#[derive(Clone, Copy, Debug)]
struct Alarm {
    id: &'static str,
    label: &'static str,
    rule: Rule,
}

/// The alarm list. Limits are the HMI's configuration, with a deadband on
/// each analog limit.
const ALARMS: &[Alarm] = &[
    Alarm {
        id: "subcooling_margin_low",
        label: "Subcooling margin low",
        rule: Rule::Subcooling {
            pressure: "pressurizer_pressure",
            temperature: "core_exit_temperature",
            limit: 15.0,
            clear: 16.0,
        },
    },
    Alarm {
        id: "pressurizer_pressure_high",
        label: "Pressurizer pressure high",
        rule: Rule::Above {
            points: &["pressurizer_pressure"],
            limit: 16.2,
            clear: 16.0,
        },
    },
    Alarm {
        id: "pressurizer_pressure_low",
        label: "Pressurizer pressure low",
        rule: Rule::Below {
            points: &["pressurizer_pressure"],
            limit: 14.5,
            clear: 14.7,
        },
    },
    Alarm {
        id: "pressurizer_level_high",
        label: "Pressurizer level high",
        rule: Rule::Above {
            points: &["pressurizer_level"],
            limit: 70.0,
            clear: 68.0,
        },
    },
    Alarm {
        id: "pressurizer_level_low",
        label: "Pressurizer level low",
        rule: Rule::Below {
            points: &["pressurizer_level"],
            limit: 30.0,
            clear: 32.0,
        },
    },
    Alarm {
        id: "hot_leg_high",
        label: "Hot leg temperature high",
        rule: Rule::Above {
            points: &["hot_leg_a", "hot_leg_b"],
            limit: 335.0,
            clear: 334.0,
        },
    },
    Alarm {
        id: "sg_level_low",
        label: "Steam generator level low",
        rule: Rule::Below {
            points: &["sg_level_a", "sg_level_b"],
            limit: 35.0,
            clear: 37.0,
        },
    },
    Alarm {
        id: "sg_level_high",
        label: "Steam generator level high",
        rule: Rule::Above {
            points: &["sg_level_a", "sg_level_b"],
            limit: 75.0,
            clear: 73.0,
        },
    },
    Alarm {
        id: "coolant_flow_low",
        label: "Coolant flow low",
        rule: Rule::Below {
            points: &["coolant_flow_a", "coolant_flow_b"],
            limit: 80.0,
            clear: 82.0,
        },
    },
    Alarm {
        id: "condenser_pressure_high",
        label: "Condenser pressure high",
        rule: Rule::Above {
            points: &["condenser_pressure"],
            limit: 12.0,
            clear: 11.0,
        },
    },
    Alarm {
        id: "neutron_power_high",
        label: "Neutron power high",
        rule: Rule::Above {
            points: &["neutron_power"],
            limit: 105.0,
            clear: 104.0,
        },
    },
    Alarm {
        id: "reactor_tripped",
        label: "Reactor tripped",
        rule: Rule::Flag {
            flags: &["reactor_tripped"],
            set: true,
        },
    },
    Alarm {
        id: "turbine_tripped",
        label: "Turbine tripped",
        rule: Rule::Flag {
            flags: &["turbine_tripped"],
            set: true,
        },
    },
    Alarm {
        id: "coolant_pump_stopped",
        label: "Coolant pump stopped",
        rule: Rule::Flag {
            flags: &["coolant_pump_a", "coolant_pump_b"],
            set: false,
        },
    },
    Alarm {
        id: "feed_pump_stopped",
        label: "Feed pump stopped",
        rule: Rule::Flag {
            flags: &["feed_pump_a", "feed_pump_b"],
            set: false,
        },
    },
    Alarm {
        id: "relief_open",
        label: "Relief valve open",
        rule: Rule::Flag {
            flags: &["pressurizer_relief", "steam_relief"],
            set: true,
        },
    },
    Alarm {
        id: "core_exit_temperature_high",
        label: "Core exit temperature high",
        rule: Rule::Above {
            points: &["core_exit_wide_range"],
            limit: 650.0,
            clear: 649.0,
        },
    },
    Alarm {
        id: "vessel_level_low",
        label: "Reactor vessel level low",
        rule: Rule::Below {
            points: &["vessel_level"],
            limit: 70.0,
            clear: 72.0,
        },
    },
    Alarm {
        id: "containment_pressure_high",
        label: "Containment pressure high",
        rule: Rule::Above {
            points: &["containment_pressure"],
            limit: 130.0,
            clear: 129.0,
        },
    },
    Alarm {
        id: "containment_hydrogen_high",
        label: "Containment hydrogen high",
        rule: Rule::Above {
            points: &["containment_hydrogen"],
            limit: 2.0,
            clear: 1.8,
        },
    },
    Alarm {
        id: "containment_radiation_high",
        label: "Containment radiation high",
        rule: Rule::Above {
            points: &["containment_radiation"],
            limit: 1.0,
            clear: 0.9,
        },
    },
    Alarm {
        id: "relief_tank_pressure_high",
        label: "Relief tank pressure high",
        rule: Rule::Above {
            points: &["relief_tank_pressure"],
            limit: 300.0,
            clear: 299.0,
        },
    },
    Alarm {
        id: "relief_tailpipe_temperature_high",
        label: "Relief tailpipe temperature high",
        rule: Rule::Above {
            points: &["relief_tailpipe_temperature"],
            limit: 100.0,
            clear: 99.0,
        },
    },
    Alarm {
        id: "turbine_building_temperature_high",
        label: "Turbine building temperature high",
        rule: Rule::Above {
            points: &["turbine_building_temperature"],
            limit: 60.0,
            clear: 59.0,
        },
    },
];

/// The number of alarm tiles.
pub const ALARM_COUNT: usize = ALARMS.len();

/// The values alarm rules read: known points and known flags.
struct Known {
    points: BTreeMap<&'static str, f64>,
    flags: BTreeMap<&'static str, bool>,
}

impl Known {
    fn of(held: &Held) -> Known {
        Known {
            points: POINTS
                .iter()
                .filter_map(|p| point_value(held, p).map(|v| (p.id, v)))
                .collect(),
            flags: FLAGS
                .iter()
                .filter_map(|f| flag_value(held, f).map(|v| (f.id, v)))
                .collect(),
        }
    }
}

impl Rule {
    /// Whether the alarm is active now, given whether it was active before.
    /// `None` when none of its values is known, so it keeps its state.
    fn decide(self, known: &Known, was_active: bool) -> Option<bool> {
        match self {
            Rule::Above {
                points,
                limit,
                clear,
            } => {
                let worst = points
                    .iter()
                    .filter_map(|id| known.points.get(id).copied())
                    .reduce(f64::max)?;
                Some(if was_active {
                    worst > clear
                } else {
                    worst > limit
                })
            }
            Rule::Below {
                points,
                limit,
                clear,
            } => {
                let worst = points
                    .iter()
                    .filter_map(|id| known.points.get(id).copied())
                    .reduce(f64::min)?;
                Some(if was_active {
                    worst < clear
                } else {
                    worst < limit
                })
            }
            Rule::Subcooling {
                pressure,
                temperature,
                limit,
                clear,
            } => {
                let margin = crate::steam::saturation(*known.points.get(pressure)?).temperature_c
                    - known.points.get(temperature)?;
                Some(margin < if was_active { clear } else { limit })
            }
            Rule::Flag { flags, set } => {
                let values: Vec<bool> = flags
                    .iter()
                    .filter_map(|id| known.flags.get(id).copied())
                    .collect();
                if values.is_empty() {
                    None
                } else {
                    Some(values.contains(&set))
                }
            }
        }
    }
}

fn update_alarms(held: &mut Held) {
    let known = Known::of(held);
    for (alarm, latch) in ALARMS.iter().zip(held.alarms.iter_mut()) {
        if let Some(active) = alarm.rule.decide(&known, latch.active) {
            if active && !latch.active {
                latch.in_ms = held.clock_ms;
            }
            if !active {
                latch.in_ms = None;
            }
            latch.active = active;
            if !active {
                latch.acknowledged = false;
            }
        }
    }
}

fn block(held: &Held, plc: Plc) -> &Block {
    &held.blocks[slot(plc)]
}

/// Rounds away the binary noise of a float product, so 1550 counts read as 15.5.
fn tidy(value: f64) -> f64 {
    (value * 1.0e6).round() / 1.0e6
}

fn point_value(held: &Held, point: &Point) -> Option<f64> {
    let block = block(held, point.plc);
    block.read_ms?;
    let count = match point.bank {
        Bank::Input => block.input.get(point.index),
        Bank::Holding => block.holding.get(point.index),
    }
    .copied()?;
    let count = f64::from(count);
    Some(tidy(match point.scale {
        Scale::Tenth => count * 0.1,
        Scale::Hundredth => count * 0.01,
    }))
}

fn flag_value(held: &Held, flag: &Flag) -> Option<bool> {
    let block = block(held, flag.plc);
    block.read_ms?;
    match flag.bank {
        BitBank::Discrete => block.discrete.get(flag.index).copied(),
        BitBank::Coil => block.coils.get(flag.index).copied(),
    }
}

fn mode_value(held: &Held, plc: Plc, index: usize) -> Option<&'static str> {
    let block = block(held, plc);
    block.read_ms?;
    block
        .coils
        .get(index)
        .map(|&auto| if auto { "automatic" } else { "manual" })
}

/// One analog value in engineering units. `value` is `null` until the
/// controller's first complete read. `stale` is true while its latest poll
/// has failed.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Reading {
    pub tag: &'static str,
    pub value: Option<f64>,
    pub unit: &'static str,
    pub stale: bool,
}

/// One controller's link state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    /// Telemetry count at the last good read, or null before the first read.
    pub heartbeat: Option<u16>,
    pub id: &'static str,
    pub online: bool,
    pub updated_at: Option<String>,
    pub error: Option<String>,
}

/// One annunciator tile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AlarmView {
    pub id: &'static str,
    pub label: &'static str,
    /// `normal`, `active` or `acknowledged`.
    pub state: &'static str,
    pub arrived_at: Option<String>,
}

/// What `/api/plant` returns.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct View {
    pub plant_time: Option<String>,
    pub zone: &'static str,
    pub links: Vec<Link>,
    pub readings: BTreeMap<&'static str, Reading>,
    /// Discrete states. `null` until the controller's first complete read.
    pub status: BTreeMap<&'static str, Option<bool>>,
    /// Controller modes: `automatic`, `manual`, or `null` before the first read.
    pub modes: BTreeMap<&'static str, Option<&'static str>>,
    pub alarms: Vec<AlarmView>,
}

/// The HMI's view of the held blocks.
pub fn view(held: &Held) -> View {
    View {
        plant_time: held.clock_ms.map(|time| held.site.timestamp(time)),
        zone: held.site.zone,
        links: PLCS
            .iter()
            .map(|&plc| {
                let b = block(held, plc);
                Link {
                    heartbeat: b
                        .read_ms
                        .and_then(|_| b.input.get(usize::from(layout(plc).input - 1)).copied()),
                    id: link_id(plc),
                    online: b.online,
                    updated_at: b.read_ms.map(|time| held.site.timestamp(time)),
                    error: b.error.clone(),
                }
            })
            .collect(),
        readings: POINTS
            .iter()
            .map(|p| {
                (
                    p.id,
                    Reading {
                        tag: p.tag,
                        value: point_value(held, p),
                        unit: p.unit,
                        stale: !block(held, p.plc).online,
                    },
                )
            })
            .collect(),
        status: FLAGS.iter().map(|f| (f.id, flag_value(held, f))).collect(),
        modes: MODES
            .iter()
            .map(|&(id, plc, index)| (id, mode_value(held, plc, index)))
            .collect(),
        alarms: ALARMS
            .iter()
            .zip(held.alarms.iter())
            .map(|(alarm, latch)| AlarmView {
                id: alarm.id,
                label: alarm.label,
                state: latch.state(),
                arrived_at: latch.in_ms.map(|time| held.site.timestamp(time)),
            })
            .collect(),
    }
}

/// Why a Modbus exchange failed.
#[derive(Debug)]
enum Failure {
    /// The connection failed or was cancelled.
    Net(ConnError),
    /// A frame or PDU did not parse or could not be written.
    Frame,
    /// The reply did not answer the request.
    Reply,
    /// The controller answered with an exception.
    Exception,
    /// The controller closed the connection before it replied.
    Closed,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Net(e) => f.write_str(match e {
                ConnError::TimedOut => "timeout",
                ConnError::Broken => "bad reply",
                _ => "refused",
            }),
            Failure::Frame | Failure::Reply | Failure::Exception => f.write_str("bad reply"),

            Failure::Closed => f.write_str("refused"),
        }
    }
}

fn deadline_failure(error: RaceError) -> Failure {
    Failure::Net(match error {
        RaceError::Deadline => ConnError::TimedOut,
        RaceError::Cancelled => ConnError::Cancelled,
    })
}

/// One Modbus/TCP session to a controller.
struct Session {
    conn: TcpConnection,
    transaction: u16,
}

impl Session {
    async fn open(fcx: &Cx, tcp: &tcp::Endpoint, to: SocketAddr) -> Result<Session, Failure> {
        let conn = fcx
            .race(Some(fcx.now() + RESPONSE_TIMEOUT), tcp.connect(fcx, to))
            .await
            .map_err(deadline_failure)?
            .map_err(Failure::Net)?;
        Ok(Session {
            conn,
            transaction: 0,
        })
    }

    /// Sends one request and reads its reply.
    async fn call(
        &mut self,
        fcx: &Cx,
        request: &modbus::Request,
    ) -> Result<modbus::Response, Failure> {
        fcx.race(
            Some(fcx.now() + RESPONSE_TIMEOUT),
            self.exchange(fcx, request),
        )
        .await
        .map_err(deadline_failure)?
    }

    async fn exchange(
        &mut self,
        fcx: &Cx,
        request: &modbus::Request,
    ) -> Result<modbus::Response, Failure> {
        self.transaction = self.transaction.wrapping_add(1);
        let transaction = self.transaction;
        let pdu = request.to_pdu().map_err(|_| Failure::Frame)?;
        let bytes = Frame {
            transaction,
            unit: UNIT,
            pdu,
        }
        .to_bytes()
        .map_err(|_| Failure::Frame)?;
        self.conn
            .write_all(fcx, &bytes)
            .await
            .map_err(Failure::Net)?;
        let mut received = Vec::new();
        loop {
            if let Some((frame, used)) =
                Frame::parse_prefix(&received).map_err(|_| Failure::Frame)?
            {
                received.drain(..used);
                if frame.transaction != transaction || frame.unit != UNIT {
                    return Err(Failure::Reply);
                }
                let (function, response) =
                    modbus::Response::parse(&frame.pdu).map_err(|_| Failure::Frame)?;
                if function != request.function() {
                    return Err(Failure::Reply);
                }
                return Ok(response);
            }
            let mut buf = [0u8; 512];
            let n = self.conn.read(fcx, &mut buf).await.map_err(Failure::Net)?;
            if n == 0 {
                return Err(Failure::Closed);
            }
            received.extend_from_slice(&buf[..n]);
        }
    }
}

async fn registers(
    fcx: &Cx,
    session: &mut Session,
    request: modbus::Request,
    quantity: u16,
) -> Result<Vec<u16>, Failure> {
    match session.call(fcx, &request).await? {
        modbus::Response::Registers(values) if values.len() == usize::from(quantity) => Ok(values),
        modbus::Response::Exception(_) => Err(Failure::Exception),
        _ => Err(Failure::Reply),
    }
}

async fn bits(
    fcx: &Cx,
    session: &mut Session,
    request: modbus::Request,
    quantity: u16,
) -> Result<Vec<bool>, Failure> {
    match session.call(fcx, &request).await? {
        // A reply carries whole bytes, so it can hold more bits than asked.
        modbus::Response::Bits(values) if values.len() >= usize::from(quantity) => {
            Ok(values[..usize::from(quantity)].to_vec())
        }
        modbus::Response::Exception(_) => Err(Failure::Exception),
        _ => Err(Failure::Reply),
    }
}

/// Reads all four blocks of one controller, in one cycle.
async fn read_controller(fcx: &Cx, session: &mut Session, plc: Plc) -> Result<Block, Failure> {
    let l = layout(plc);
    let input = registers(
        fcx,
        session,
        modbus::Request::ReadInputRegisters {
            address: 0,
            quantity: l.input,
        },
        l.input,
    )
    .await?;
    let discrete = bits(
        fcx,
        session,
        modbus::Request::ReadDiscreteInputs {
            address: 0,
            quantity: l.discrete,
        },
        l.discrete,
    )
    .await?;
    let coils = if l.coils == 0 {
        Vec::new()
    } else {
        bits(
            fcx,
            session,
            modbus::Request::ReadCoils {
                address: 0,
                quantity: l.coils,
            },
            l.coils,
        )
        .await?
    };
    let holding = if l.holding == 0 {
        Vec::new()
    } else {
        registers(
            fcx,
            session,
            modbus::Request::ReadHoldingRegisters {
                address: 0,
                quantity: l.holding,
            },
            l.holding,
        )
        .await?
    };
    Ok(Block {
        input,
        discrete,
        coils,
        holding,
        read_ms: Some(run_ms(fcx)),
        online: true,
        error: None,
    })
}

fn run_ms(fcx: &Cx) -> i64 {
    i64::try_from(fcx.now().since_start().as_millis()).unwrap_or(i64::MAX)
}

fn mark_offline(held: &Mutex<Held>, plc: Plc, error: String) {
    let mut state = held.lock();
    let block = &mut state.blocks[slot(plc)];
    block.online = false;
    block.error = Some(error);
}

/// The poll task. It runs one cycle per [`POLL_MS`] of run time until the
/// region is cancelled.
async fn poll(
    fcx: Cx,
    machine: Machine,
    controllers: Controllers,
    held: Arc<Mutex<Held>>,
) -> fictionet::Result {
    let tcp = machine.tcp.clone();
    let mut sessions: [Option<Session>; PLCS.len()] = std::array::from_fn(|_| None);
    while !fcx.is_cancelled() {
        for plc in PLCS {
            let at = slot(plc);
            if sessions[at].is_none() {
                match Session::open(&fcx, &tcp, controllers.of(plc)).await {
                    Ok(session) => sessions[at] = Some(session),
                    Err(e) => {
                        mark_offline(&held, plc, e.to_string());
                        continue;
                    }
                }
            }
            let Some(session) = sessions[at].as_mut() else {
                continue;
            };
            match read_controller(&fcx, session, plc).await {
                Ok(block) => held.lock().blocks[at] = block,
                Err(e) => {
                    sessions[at] = None;
                    mark_offline(&held, plc, e.to_string());
                }
            }
        }
        {
            let clock = run_ms(&fcx);
            let mut state = held.lock();
            state.clock_ms = Some(clock);
            update_alarms(&mut state);
            state.sample();
        }
        if fcx.sleep(Duration::from_millis(POLL_MS)).await.is_err() {
            break;
        }
    }
    Ok(())
}

/// Accepts connections on port 80 and serves each one with `handler`.
async fn serve(
    fcx: Cx,
    mut listener: tcp::Listener,
    handler: Arc<dyn Handler>,
    local: SocketAddr,
    site: Site,
) -> fictionet::Result {
    let mut id = 0u64;
    loop {
        let Ok(conn) = listener.accept(&fcx).await else {
            return Ok(());
        };
        id += 1;
        let info = ConnInfo::new(id, local, conn.peer_addr());
        let handler = handler.clone();
        fcx.spawn(move |fcx| async move {
            let options = HttpOptions {
                date: Some(std::time::UNIX_EPOCH + Duration::from_secs(site.epoch)),
                ..HttpOptions::default()
            };
            let _ = httpd::serve_connection(&fcx, conn, info, handler, &options).await;
            Ok(())
        });
    }
}

/// Starts hmi01 on its machine: the poll task and the HTTP server on port 80.
/// Returns the state the poll task keeps. The machine must be the one
/// [`network`] attached.
pub fn start(
    fcx: &Cx,
    machine: Machine,
    controllers: Controllers,
    site: Site,
    driver: &Driver,
) -> Result<Arc<Mutex<Held>>, Error> {
    let held = Arc::new(Mutex::new(Held::warm(site, driver)));
    let tcp = machine.tcp.clone();
    let listener = tcp.listen(PORT)?;
    let handler: Arc<dyn Handler> = Arc::new(WebServer(router(held.clone(), tcp, controllers)));
    let local = SocketAddr::new(IpAddr::V4(ADDR), PORT);
    fcx.spawn(move |fcx| serve(fcx, listener, handler, local, site));
    let poll_state = held.clone();
    fcx.spawn(move |fcx| poll(fcx, machine, controllers, poll_state));
    Ok(held)
}

struct WebServer(Router);

fn server_header<T>(mut response: Response<T>) -> Response<T> {
    response
        .headers_mut()
        .insert(header::SERVER, HeaderValue::from_static("GoAhead-Webs"));
    response
}

impl Handler for WebServer {
    fn call(&self, request: Request<httpd::Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        match self.0.call(request, ex) {
            httpd::Reply::Now(response) => httpd::Reply::Now(server_header(response)),
            httpd::Reply::Later(work) => httpd::Reply::Later(Box::new(move |fcx| {
                Box::pin(async move { work(fcx).await.map(server_header) })
            })),
            reply => reply,
        }
    }
}

fn router(held: Arc<Mutex<Held>>, tcp: tcp::Endpoint, controllers: Controllers) -> Router {
    let plant = held.clone();
    let history = held.clone();
    Router::new()
        .get("/", |_, _| {
            respond(
                StatusCode::OK,
                "text/html; charset=utf-8",
                Bytes::from_static(INDEX_HTML.as_bytes()),
            )
        })
        .get("/hmi.css", |_, _| {
            respond(
                StatusCode::OK,
                "text/css; charset=utf-8",
                Bytes::from_static(STYLE_CSS.as_bytes()),
            )
        })
        .get("/hmi.mjs", |_, _| {
            respond(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                Bytes::from_static(SCRIPT_JS.as_bytes()),
            )
        })
        .get("/api/plant", move |_, _| {
            json(StatusCode::OK, &view(&plant.lock()))
        })
        .get("/api/trend", move |_, request| {
            let query: BTreeMap<_, _> = request
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .filter_map(|part| part.split_once('='))
                .collect();
            let point = query.get("point").copied().unwrap_or_default();
            let minutes = query
                .get("minutes")
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(10);
            match history.lock().trend(point, minutes) {
                Some(samples) => json(
                    StatusCode::OK,
                    &serde_json::json!({ "point": point, "samples": samples }),
                ),
                None => refusal(StatusCode::NOT_FOUND, "unknown point", None),
            }
        })
        .route_async(Some(Method::POST), "/api/control/*", move |fcx, request| {
            control(fcx, tcp.clone(), controllers, held.clone(), request)
        })
}

/// One control: the register or coil it writes, and whether it acknowledges
/// the alarms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    Coil { address: u16, value: bool },
    Register { address: u16, value: u16 },
}

impl Write {
    fn request(self) -> modbus::Request {
        match self {
            Write::Coil { address, value } => modbus::Request::WriteSingleCoil { address, value },
            Write::Register { address, value } => {
                modbus::Request::WriteSingleRegister { address, value }
            }
        }
    }

    /// The reply a controller gives when it accepts this write.
    fn echo(self) -> modbus::Response {
        match self {
            Write::Coil { address, value } => modbus::Response::WriteSingleCoil { address, value },
            Write::Register { address, value } => {
                modbus::Response::WriteSingleRegister { address, value }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Order {
    plc: Plc,
    write: Write,
    acknowledge: bool,
}

/// The body of a control POST. Each control reads the fields it needs.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Body {
    name: Option<String>,
    percent: Option<f64>,
    running: Option<bool>,
    auto: Option<bool>,
    on: Option<bool>,
    open: Option<bool>,
    closed: Option<bool>,
}

fn need<T>(value: Option<T>, field: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("the control needs {field}"))
}

/// A percent from 0 to 100, as tenths of a percent (`rod`) or permille
/// (`valve`): both are the percent times ten.
fn tenths(body: &Body) -> Result<u16, String> {
    let percent = need(body.percent, "percent")?;
    if !(0.0..=100.0).contains(&percent) {
        return Err("percent must be from 0 to 100".to_owned());
    }
    Ok((percent * 10.0).round() as u16)
}

fn pump_coil(name: &str) -> Option<(Plc, u16)> {
    match name {
        "safety-injection" => Some((Plc::Rcs1, 6)),
        "coolant-a" => Some((Plc::Rcs1, 0)),
        "coolant-b" => Some((Plc::Rcs1, 1)),
        "feed-a" => Some((Plc::Bop1, 0)),
        "feed-b" => Some((Plc::Bop1, 1)),
        "aux-feed" => Some((Plc::Bop1, 2)),
        "circ-water" => Some((Plc::Bop1, 3)),
        _ => None,
    }
}

fn valve_register(name: &str) -> Option<(Plc, u16)> {
    match name {
        "feed-a" => Some((Plc::Bop1, 0)),
        "feed-b" => Some((Plc::Bop1, 1)),
        "turbine" => Some((Plc::Bop1, 2)),
        "steam-dump" => Some((Plc::Bop1, 3)),
        "spray" => Some((Plc::Rcs1, 0)),
        _ => None,
    }
}

fn controller_coil(name: &str) -> Option<(Plc, u16)> {
    match name {
        "pressurizer" => Some((Plc::Rcs1, 3)),
        "feed-a" => Some((Plc::Bop1, 4)),
        "feed-b" => Some((Plc::Bop1, 5)),
        "steam-dump" => Some((Plc::Bop1, 6)),
        _ => None,
    }
}

/// The write for a control POST. `kind` is the path after `/api/control/`.
fn order(kind: &str, body: &Body) -> Result<Order, String> {
    let coil = |plc, address, value| Order {
        plc,
        write: Write::Coil { address, value },
        acknowledge: false,
    };
    match kind {
        "relief" => Ok(coil(Plc::Rcs1, 4, need(body.open, "open")?)),
        "relief-block" => Ok(coil(Plc::Rcs1, 5, need(body.closed, "closed")?)),
        "steam-isolation" => Ok(coil(Plc::Bop1, 7, need(body.closed, "closed")?)),
        "rod-demand" => Ok(Order {
            plc: Plc::Rps1,
            write: Write::Register {
                address: 0,
                value: tenths(body)?,
            },
            acknowledge: false,
        }),
        "pump" => {
            let name = need(body.name.as_deref(), "a pump name")?;
            let (plc, address) = pump_coil(name).ok_or_else(|| format!("no pump called {name}"))?;
            Ok(coil(plc, address, need(body.running, "running")?))
        }
        "valve" => {
            let name = need(body.name.as_deref(), "a valve name")?;
            let (plc, address) =
                valve_register(name).ok_or_else(|| format!("no valve called {name}"))?;
            Ok(Order {
                plc,
                write: Write::Register {
                    address,
                    value: tenths(body)?,
                },
                acknowledge: false,
            })
        }
        "controller" => {
            let name = need(body.name.as_deref(), "a controller name")?;
            let (plc, address) =
                controller_coil(name).ok_or_else(|| format!("no controller called {name}"))?;
            Ok(coil(plc, address, need(body.auto, "auto")?))
        }
        "heaters" => Ok(coil(Plc::Rcs1, 2, need(body.on, "on")?)),
        "trip" => Ok(coil(Plc::Rps1, 0, true)),
        "reset" => Ok(coil(Plc::Rps1, 1, true)),
        "acknowledge" => Ok(Order {
            acknowledge: true,
            ..coil(Plc::Rps1, 2, true)
        }),
        _ => Err(format!("no control called {kind}")),
    }
}

/// The status an exception answers with. The controller refusing in its
/// present state is a conflict. A value or address it does not take is a bad
/// request.
fn status_of(exception: Exception) -> StatusCode {
    match exception {
        Exception::ServerDeviceFailure => StatusCode::CONFLICT,
        Exception::IllegalFunction
        | Exception::IllegalDataAddress
        | Exception::IllegalDataValue => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    }
}

/// Carries out one control POST: one write on its controller, over a session
/// of its own.
async fn control(
    fcx: Cx,
    tcp: tcp::Endpoint,
    controllers: Controllers,
    held: Arc<Mutex<Held>>,
    request: Request<Bytes>,
) -> Response<Bytes> {
    let kind = request
        .uri()
        .path()
        .strip_prefix(CONTROL_PREFIX)
        .unwrap_or_default();
    let body = if request.body().is_empty() {
        Ok(Body::default())
    } else {
        serde_json::from_slice::<Body>(request.body())
    };
    let body = match body {
        Ok(body) => body,
        Err(e) => return refusal(StatusCode::BAD_REQUEST, &format!("bad body: {e}"), None),
    };
    let order = match order(kind, &body) {
        Ok(order) => order,
        Err(reason) => return refusal(StatusCode::BAD_REQUEST, &reason, None),
    };
    let to = controllers.of(order.plc);
    let sent = async {
        let mut session = Session::open(&fcx, &tcp, to).await?;
        session.call(&fcx, &order.write.request()).await
    };
    match sent.await {
        Ok(modbus::Response::Exception(e)) => refusal(status_of(e), &e.to_string(), Some(e.code())),
        Ok(reply) if reply == order.write.echo() => {
            if order.acknowledge {
                held.lock().acknowledge();
            }
            json(StatusCode::OK, &serde_json::json!({ "ok": true }))
        }
        Ok(_) => refusal(
            StatusCode::BAD_GATEWAY,
            "the controller did not echo the write",
            None,
        ),
        Err(failure) => refusal(StatusCode::BAD_GATEWAY, &failure.to_string(), None),
    }
}

fn refusal(status: StatusCode, reason: &str, exception: Option<u8>) -> Response<Bytes> {
    json(
        status,
        &serde_json::json!({ "ok": false, "reason": reason, "exception": exception }),
    )
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Bytes> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut response = respond(status, "application/json; charset=utf-8", Bytes::from(body));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn respond(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Bytes> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registers;
    use crate::{Config, Plant};

    fn ready() -> Held {
        let mut held = Held::default();
        let snapshot = Plant::new(Config::default()).snapshot();
        for plc in PLCS {
            let l = layout(plc);
            held.blocks[slot(plc)] = Block {
                input: registers::input_registers(plc, &snapshot),
                discrete: registers::discrete_inputs(plc, &snapshot),
                coils: registers::coils(plc, &snapshot),
                holding: registers::holding_registers(plc, &snapshot),
                read_ms: Some(2_000),
                online: true,
                error: None,
            };
            assert_eq!(held.blocks[slot(plc)].input.len(), usize::from(l.input));
        }
        held
    }

    #[test]
    fn post_accident_alarm_rules_apply_limits_and_clear_deadbands() {
        for (id, point, limit, clear, below) in [
            (
                "core_exit_temperature_high",
                "core_exit_wide_range",
                650.0,
                649.0,
                false,
            ),
            ("vessel_level_low", "vessel_level", 70.0, 72.0, true),
            (
                "containment_pressure_high",
                "containment_pressure",
                130.0,
                129.0,
                false,
            ),
            (
                "containment_hydrogen_high",
                "containment_hydrogen",
                2.0,
                1.8,
                false,
            ),
            (
                "containment_radiation_high",
                "containment_radiation",
                1.0,
                0.9,
                false,
            ),
            (
                "relief_tank_pressure_high",
                "relief_tank_pressure",
                300.0,
                299.0,
                false,
            ),
            (
                "relief_tailpipe_temperature_high",
                "relief_tailpipe_temperature",
                100.0,
                99.0,
                false,
            ),
            (
                "turbine_building_temperature_high",
                "turbine_building_temperature",
                60.0,
                59.0,
                false,
            ),
        ] {
            let alarm = ALARMS.iter().find(|a| a.id == id).expect(id);
            for (value, latched, expected) in [
                (limit, false, false),
                (if below { limit - 0.01 } else { limit + 0.01 }, false, true),
                ((limit + clear) / 2.0, true, true),
                (clear, true, false),
            ] {
                let known = Known {
                    points: BTreeMap::from([(point, value)]),
                    flags: BTreeMap::new(),
                };
                assert_eq!(
                    alarm.rule.decide(&known, latched),
                    Some(expected),
                    "{id}: {value}"
                );
            }
        }
    }

    #[test]
    fn warm_history_uses_encoded_model_samples_and_leaves_the_live_plant_unchanged() {
        for initial_power in [crate::InitialPower::Full, crate::InitialPower::Half] {
            let config = Config {
                initial_power,
                seed: 29,
                ..Config::default()
            };
            let driver = Driver::new(config.clone());
            let before = driver.snapshot();
            let site = Site {
                utc_offset_seconds: 19_800,
                zone: "IST",
                ..Site::default()
            };
            let held = Held::warm(site, &driver);
            assert_eq!(driver.snapshot(), before);
            assert!(
                view(&held)
                    .links
                    .iter()
                    .all(|link| !link.online && link.updated_at.is_none())
            );
            let mut expected = Plant::new(config);
            for n in 0..HISTORY_CAPACITY {
                expected.advance(n as u64 * POLL_MS);
                let snapshot = expected.snapshot();
                for point in POINTS {
                    let registers = match point.bank {
                        Bank::Input => registers::input_registers(point.plc, &snapshot),
                        Bank::Holding => registers::holding_registers(point.plc, &snapshot),
                    };
                    let count = registers[point.index];
                    let expected_value = match point.scale {
                        Scale::Tenth => f64::from(count) / 10.0,
                        Scale::Hundredth => f64::from(count) / 100.0,
                    };
                    let sample = &held.history[point.id][n];
                    assert_eq!(sample.value, Some(expected_value), "{} at {n}", point.id);
                    assert_eq!(sample.time, site.timestamp(-600_000 + n as i64 * 250));
                }
            }
            let samples = held.trend("hot_leg_a", 10).unwrap();
            assert_eq!(samples.len(), HISTORY_CAPACITY);
            assert_eq!(
                samples.last().unwrap().clock_ms - samples[0].clock_ms,
                600_000
            );
            assert!(
                samples
                    .windows(2)
                    .all(|pair| pair[1].clock_ms - pair[0].clock_ms == 250)
            );
            assert!(
                samples
                    .windows(2)
                    .any(|pair| pair[0].value != pair[1].value)
            );
            driver.advance_to(&(), 10_000);
            let mut fresh = Plant::new(Config {
                initial_power,
                seed: 29,
                ..Config::default()
            });
            fresh.advance(10_000);
            assert_eq!(driver.snapshot(), fresh.snapshot());
        }
    }

    #[test]
    fn layouts_match_the_register_map() {
        let snapshot = Plant::new(Config::default()).snapshot();
        for plc in PLCS {
            let l = layout(plc);
            assert_eq!(
                registers::input_registers(plc, &snapshot).len(),
                usize::from(l.input),
                "{plc:?} input registers"
            );
            assert_eq!(
                registers::discrete_inputs(plc, &snapshot).len(),
                usize::from(l.discrete),
                "{plc:?} discrete inputs"
            );
            assert_eq!(
                registers::coils(plc, &snapshot).len(),
                usize::from(l.coils),
                "{plc:?} coils"
            );
            assert_eq!(
                registers::holding_registers(plc, &snapshot).len(),
                usize::from(l.holding),
                "{plc:?} holding registers"
            );
        }
    }

    #[test]
    fn counts_become_engineering_units() {
        let held = ready();
        let view = view(&held);
        assert_eq!(view.readings["pressurizer_pressure"].value, Some(15.5));
        assert_eq!(view.readings["hot_leg_a"].value, Some(325.0));
        assert_eq!(view.readings["neutron_power"].value, Some(100.0));
        assert_eq!(view.readings["rod_demand"].value, Some(50.0));
        assert_eq!(view.readings["pressurizer_pressure"].unit, "MPa");
    }

    #[test]
    fn nothing_read_yet_is_null_not_zero() {
        let view = view(&Held::default());
        assert_eq!(view.readings["pressurizer_pressure"].value, None);
        assert_eq!(view.status["reactor_tripped"], None);
        assert_eq!(view.modes["pressurizer"], None);
        assert!(view.links.iter().all(|link| link.heartbeat.is_none()));
        assert!(view.readings["pressurizer_pressure"].stale);
    }

    #[test]
    fn a_failed_poll_keeps_the_last_values_and_marks_them_stale() {
        let mut held = ready();
        mark_offline_state(&mut held, Plc::Rcs1, "connection refused".to_owned());
        let view = view(&held);
        assert_eq!(view.readings["pressurizer_pressure"].value, Some(15.5));
        assert!(view.readings["pressurizer_pressure"].stale);
        assert!(!view.readings["neutron_power"].stale);
        assert!(!view.links[1].online);
    }

    fn mark_offline_state(held: &mut Held, plc: Plc, error: String) {
        let block = &mut held.blocks[slot(plc)];
        block.online = false;
        block.error = Some(error);
    }

    #[test]
    fn status_and_modes_come_from_the_discrete_inputs_and_coils() {
        let held = ready();
        let view = view(&held);
        assert_eq!(view.status["reactor_tripped"], Some(false));
        assert_eq!(view.status["coolant_pump_a"], Some(true));
        assert_eq!(view.status["auxiliary_feed"], Some(false));
        assert_eq!(view.modes["pressurizer"], Some("automatic"));
    }

    #[test]
    fn subcooling_alarm_has_a_deadband_and_keeps_state_when_unknown() {
        let rule = ALARMS
            .iter()
            .find(|alarm| alarm.id == "subcooling_margin_low")
            .unwrap()
            .rule;
        let mut known = Known {
            points: BTreeMap::new(),
            flags: BTreeMap::new(),
        };
        let pressure = 15.5;
        let saturation = crate::steam::saturation(pressure).temperature_c;
        known.points.insert("pressurizer_pressure", pressure);
        let mut active = false;
        for (margin, expected) in [(14.9, true), (15.5, true), (16.1, false), (15.5, false)] {
            known
                .points
                .insert("core_exit_temperature", saturation - margin);
            active = rule.decide(&known, active).unwrap();
            assert_eq!(active, expected);
        }
        known.points.remove("pressurizer_pressure");
        assert_eq!(rule.decide(&known, true), None);
        known.points.insert("pressurizer_pressure", pressure);
        known.points.remove("core_exit_temperature");
        assert_eq!(rule.decide(&known, false), None);
    }

    #[test]
    fn analog_alarms_use_a_deadband() {
        let mut held = ready();
        let set = |held: &mut Held, count: u16| held.blocks[slot(Plc::Rcs1)].input[4] = count;
        let state = |held: &Held| {
            view(held)
                .alarms
                .iter()
                .find(|a| a.id == "pressurizer_pressure_high")
                .map(|a| a.state)
                .unwrap_or("missing")
        };
        set(&mut held, 1_630);
        update_alarms(&mut held);
        assert_eq!(state(&held), "active");
        set(&mut held, 1_610);
        update_alarms(&mut held);
        assert_eq!(
            state(&held),
            "active",
            "inside the deadband it stays active"
        );
        set(&mut held, 1_600);
        update_alarms(&mut held);
        assert_eq!(state(&held), "normal", "at the clear value it clears");
        set(&mut held, 1_610);
        update_alarms(&mut held);
        assert_eq!(
            state(&held),
            "normal",
            "above the clear value it does not raise"
        );
    }

    #[test]
    fn acknowledged_alarms_stay_acknowledged_until_they_clear() {
        let mut held = ready();
        held.blocks[slot(Plc::Bop1)].discrete[5] = true;
        update_alarms(&mut held);
        held.acknowledge();
        let state = |held: &Held| {
            view(held)
                .alarms
                .iter()
                .find(|a| a.id == "turbine_tripped")
                .map(|a| a.state)
                .unwrap_or("missing")
        };
        assert_eq!(state(&held), "acknowledged");
        held.blocks[slot(Plc::Bop1)].discrete[5] = false;
        update_alarms(&mut held);
        assert_eq!(state(&held), "normal");
        held.blocks[slot(Plc::Bop1)].discrete[5] = true;
        update_alarms(&mut held);
        assert_eq!(state(&held), "active", "a new trip is not acknowledged");
    }

    #[test]
    fn a_rod_demand_becomes_tenths_of_a_percent() {
        let body = Body {
            percent: Some(48.0),
            ..Body::default()
        };
        assert_eq!(
            order("rod-demand", &body),
            Ok(Order {
                plc: Plc::Rps1,
                write: Write::Register {
                    address: 0,
                    value: 480
                },
                acknowledge: false,
            })
        );
    }

    #[test]
    fn controls_map_to_their_coils_and_registers() {
        let pump = Body {
            name: Some("coolant-b".to_owned()),
            running: Some(false),
            ..Body::default()
        };
        assert_eq!(
            order("pump", &pump).map(|o| (o.plc, o.write)),
            Ok((
                Plc::Rcs1,
                Write::Coil {
                    address: 1,
                    value: false
                }
            ))
        );
        let valve = Body {
            name: Some("spray".to_owned()),
            percent: Some(25.0),
            ..Body::default()
        };
        assert_eq!(
            order("valve", &valve).map(|o| (o.plc, o.write)),
            Ok((
                Plc::Rcs1,
                Write::Register {
                    address: 0,
                    value: 250
                }
            ))
        );
        let controller = Body {
            name: Some("steam-dump".to_owned()),
            auto: Some(true),
            ..Body::default()
        };
        assert_eq!(
            order("controller", &controller).map(|o| (o.plc, o.write)),
            Ok((
                Plc::Bop1,
                Write::Coil {
                    address: 6,
                    value: true
                }
            ))
        );
        let ack = order("acknowledge", &Body::default());
        assert_eq!(
            ack,
            Ok(Order {
                plc: Plc::Rps1,
                write: Write::Coil {
                    address: 2,
                    value: true
                },
                acknowledge: true,
            })
        );
        assert_eq!(
            order("trip", &Body::default()).map(|o| o.write),
            Ok(Write::Coil {
                address: 0,
                value: true
            })
        );
    }

    #[test]
    fn bad_controls_are_refused_before_any_write() {
        let high = Body {
            percent: Some(120.0),
            ..Body::default()
        };
        assert!(order("rod-demand", &high).is_err());
        assert!(order("rod-demand", &Body::default()).is_err());
        assert!(order("pump", &Body::default()).is_err());
        let unknown = Body {
            name: Some("coolant-c".to_owned()),
            running: Some(true),
            ..Body::default()
        };
        assert!(order("pump", &unknown).is_err());
        assert!(order("shutdown", &Body::default()).is_err());
    }

    #[test]
    fn the_write_echo_matches_its_request() {
        let write = Write::Register {
            address: 0,
            value: 480,
        };
        assert_eq!(
            write.request(),
            modbus::Request::WriteSingleRegister {
                address: 0,
                value: 480
            }
        );
        assert_eq!(
            write.echo(),
            modbus::Response::WriteSingleRegister {
                address: 0,
                value: 480
            }
        );
    }

    #[test]
    fn controller_exceptions_map_to_statuses() {
        assert_eq!(
            status_of(Exception::IllegalDataValue),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(Exception::ServerDeviceFailure),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn the_controller_addresses_follow_the_network() {
        let c = controllers();
        assert_eq!(c.of(Plc::Rps1).to_string(), "192.168.95.11:502");
        assert_eq!(c.of(Plc::Rcs1).to_string(), "192.168.95.12:502");
        assert_eq!(c.of(Plc::Bop1).to_string(), "192.168.95.13:502");
    }
}
