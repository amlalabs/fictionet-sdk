//! Nuclear is a fictional educational two-loop pressurized water reactor.
//! It is a training simulator for Fictionet, at undergraduate dynamics level.
//! It is not a design tool or a safety analysis tool. Its round numbers do
//! not represent a particular plant, operating procedure, or licensed limit.
//!
//! Six delayed neutron groups drive prompt-jump kinetics. Temperature feedback
//! couples a fuel node to a core coolant node and three mixed nodes per loop.
//! Steam generators, feedwater, a pressurizer, turbine, steam dump and condenser
//! close the heat balance. Initial conditions are full or half power in equilibrium.
//! Constants and their units are listed in the modules that use them. Plant
//! capacities and controller gains are approximate educational tuning values.
//!
//! Plant time is integer milliseconds. Call [`Plant::advance`] with an absolute
//! target; only complete 50 ms steps run. Earlier targets do nothing. Commands
//! set control demands or fault state at the current time; physical effects
//! begin next step. Scheduled changes run before the physics on the first step
//! at or after their time. Equal-time schedule entries use array order.
//! No model code reads a clock, socket, environment variable or global state.
//! Basic IEEE-754 arithmetic, fixed iteration order and an integer noise
//! generator give reproducible trajectories, including on wasm32. No fused
//! operations or platform transcendental functions are used.
//!
//! True state and reported instruments are separate. Protection reads its own
//! true-value channels. Local automatic process controllers also use noiseless
//! measurements; network display faults do not alter those local controllers.
//! Alarms use reported readings and equipment status. Quiet or stuck instruments
//! can conceal an alarm. With automatic protection disabled, the operator must
//! respond to the physics even when the displayed readings lie. Condenser
//! vacuum protection still trips the turbine. Manual reactor trip always works.
//!
//! Transport delays, shrink and swell, charging and letdown, xenon and boron,
//! spatial effects, two-phase primary flow, fuel damage, containment, real
//! protection channel redundancy, electrical buses and pump heat are omitted.
//! Primary inventory is constant. Secondary liquid is treated as saturated;
//! its sensible heat storage and feedwater subcooling transients are omitted.
//! Relief is an ideal pressure limiter. Excess secondary water over full scale
//! drains away. There is no emergency core cooling or cold shutdown model.
//! The prompt approximation clamps reactivity to 0.9 beta and power to ten times
//! rated. Leaving a thermal model boundary also latches `model_limit`. Values
//! after a limit are outside the model. Primary coolant reaching saturation
//! at pressurizer pressure latches the limit. Core exit subcooling margin is
//! 19.79 C at full power. Automatic heaters run at 25% to balance ambient loss.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`kinetics`] | Precursors, reactivity response and decay heat |
//! | [`plant`] | Time, energy balances, controls and command application |
//! | [`steam`] | Coarse saturation table |
//! | [`protection`] | True-channel trips and reported-channel alarms |
//! | [`registers`] | Modbus register map and telemetry heartbeats of the three controllers |
//! | [`sensors`] | Instrument ranges, lag, noise and sampling |
//! | [`faults`] | Fixed fault slots and schedules |
//! | [`command`] | Integer commands and replies |
//! | [`snapshot`] | Bounded projection for a future state topic |
//! | [`driver`] | Shared handle that owns the plant behind a mutex |
//! | [`plc`] | Modbus/TCP service of one controller over the shared plant |
//! | [`facts`] | Plant facts for the Fictionet event log |
//! | [`hmi`] | Supervisory client hmi01: polls the controllers, serves the mimic page and control API |
//! | [`network`] | Operations and control networks, with the controllers on port 502 |
//! | [`story`] | The scripted operator story: six steps with automatic protection off |
//!
//! Loops are loop A and loop B, in that array order.
//! Commands use externally tagged serde enums with snake_case wire names. Rod positions use tenths of a
//! percent; valve demands use permille. Sensor fault values use signed counts
//! of the sensor resolution. For example, a stuck 3250 hot-leg count is 325 C.
//! Every accepted operator command increments `operator_actions`; only fault
//! changes, reactor trips and resets increment `revision`. Rejected commands
//! change neither counter. The first accepted command after the most recent
//! fault start sets `first_action_after_fault_ms` to its delay. Later commands
//! keep it; each new fault start clears it. Clearing a fault does not restart
//! a stopped pump. Telemetry quiet freezes readings and reported equipment
//! status together; controller modes remain live.
//! Fault slots and the schedule are fixed arrays, so overflow cannot be built.
//! The viewer example, `examples/viewer.rs`, runs the plant in real time and
//! serves the control room page with scripted steps and plant moments. The operator
//! reads and commands through hmi01. The checks read plant truth. Each HMI link
//! shows a telemetry heartbeat that stops when the feed freezes; polls keep counting.
//!
//! ```
//! use nuclear_world::{Plant, Config, command::{Command, FaultCommand}};
//! let mut plant = Plant::new(Config::default());
//! let command: Command = serde_json::from_str(
//!     r#"{"rod_demand":{"tenths_percent":480}}"#).unwrap();
//! plant.apply(command).unwrap();
//! let fault: FaultCommand = serde_json::from_str(
//!     r#"{"change":{"inject":{"sensor":{"sensor":{"hot_leg":"a"},"kind":{"stuck":{"value":3250}}}}},"expected_revision":0}"#).unwrap();
//! plant.apply_fault(fault).unwrap();
//! plant.advance(1000);
//! assert_eq!(plant.snapshot().at_ms, 1000);
//! ```
//!
//! # Sources
//!
//! - John R. Lamarsh and Anthony J. Baratta, *Introduction to Nuclear
//!   Engineering*, third edition, Prentice Hall, 2001. Point kinetics,
//!   delayed neutron groups and the prompt jump treatment. [Publisher](https://www.pearson.com/en-us/subject-catalog/p/introduction-to-nuclear-engineering/P200000003494).
//! - Thomas W. Kerlin and Belle R. Upadhyaya, *Dynamics and Control of Nuclear
//!   Reactors*, Academic Press, 2019. Lumped plant dynamics and control.
//!   [Publisher](https://www.sciencedirect.com/book/monograph/9780128152614/dynamics-and-control-of-nuclear-reactors).
//! - U.S. Nuclear Regulatory Commission, *Westinghouse Technology Systems
//!   Manual*. PWR systems and control functions. [NRC document](https://www.nrc.gov/docs/ML0230/ML023040131.pdf).
//!   Values here are representative round choices, not reproduced setpoints.
//! - IAPWS, *Revised Release on the IAPWS Industrial Formulation 1997 for the
//!   Thermodynamic Properties of Water and Steam*, R7-97(2012).
//!   [Release](https://iapws.org/technical-guidance/release/IF97-Rev).
//!   The coarse table follows saturation properties; it does not implement
//!   the release's accuracy or full domain.
//! - K. Way and E. P. Wigner, “The Rate of Decay of Fission Products,”
//!   *Physical Review* 73, 1318 (1948), [doi:10.1103/PhysRev.73.1318](https://doi.org/10.1103/PhysRev.73.1318).
//!   The long-irradiation comparison used here is 0.066 t^-0.2 for t in seconds.

pub mod command;
pub mod driver;
pub mod facts;
pub mod faults;
pub mod hmi;
pub mod kinetics;
pub mod network;
pub mod plant;
pub mod plc;
pub mod protection;
pub mod registers;
pub mod sensors;
pub mod snapshot;
pub mod steam;
pub mod story;

pub use plant::{Config, InitialPower, Plant};
