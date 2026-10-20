//! A shared handle to one plant.
//!
//! [`Driver`] owns a [`Plant`] behind a mutex, so a PLC service and the
//! network can use the same plant from different threads. It reads no clock
//! and does no I/O. The caller supplies the plant time to advance to.
//!
//! The methods that change the plant take a [`Sink`] for the facts the change
//! makes. Each one reads the plant before and after the change under one lock,
//! then delivers the facts after the lock is released. [`Driver::apply`] logs
//! the trips and the first action that its command makes, but not the action
//! itself. The caller knows the command's source, so it logs the action with
//! [`facts::action`].

use std::sync::Arc;

use fictionet::sync::Mutex;

use crate::command::{Applied, Command, FaultCommand, Rejected};
use crate::facts::{self, Sink};
use crate::snapshot::PlantSnapshot;
use crate::{Config, Plant};

/// A cheaply cloneable, thread-safe handle to one plant. Clones share the plant.
#[derive(Clone)]
pub struct Driver {
    plant: Arc<Mutex<Plant>>,
}

impl Driver {
    /// Starts a plant built from `config` at plant time zero.
    pub fn new(config: Config) -> Driver {
        Driver {
            plant: Arc::new(Mutex::new(Plant::new(config))),
        }
    }

    /// Returns a clone of the shared plant, so other services can use it.
    pub fn plant(&self) -> Arc<Mutex<Plant>> {
        Arc::clone(&self.plant)
    }

    /// Advances the plant to the absolute time `to_ms`. Only whole 50 ms steps
    /// run, and an earlier target does nothing. Delivers a trip the advance
    /// latched, and, when the plant time crosses a divergence sample, one line
    /// for each active sensor fault.
    pub fn advance_to(&self, sink: &impl Sink, to_ms: u64) {
        let (before, after, ()) = self.act(|plant| plant.advance(to_ms));
        facts::changes(sink, &before, &after);
        if facts::divergence_due(before.at_ms, after.at_ms) {
            facts::divergence(sink, &after);
        }
    }

    /// Returns the plant's state at the current plant time.
    pub fn snapshot(&self) -> PlantSnapshot {
        self.plant.lock().snapshot()
    }

    /// Applies an operator command at the current plant time. Delivers the trip
    /// or the first action that the command makes. It does not deliver the
    /// action itself, which the caller logs with its source.
    pub fn apply(&self, sink: &impl Sink, command: Command) -> Result<Applied, Rejected> {
        let (before, after, result) = self.act(|plant| plant.apply(command));
        if result.is_ok() {
            facts::changes(sink, &before, &after);
        }
        result
    }

    /// Applies a fault change at the current plant time, and delivers the fault.
    pub fn apply_fault(
        &self,
        sink: &impl Sink,
        command: FaultCommand,
    ) -> Result<Applied, Rejected> {
        let (_, after, result) = self.act(|plant| plant.apply_fault(command));
        if result.is_ok() {
            facts::fault(sink, command.change, &after);
        }
        result
    }

    /// Runs `act` on the plant. Returns the snapshots before and after it, read
    /// under the same lock, and the result of `act`.
    fn act<T>(&self, act: impl FnOnce(&mut Plant) -> T) -> (PlantSnapshot, PlantSnapshot, T) {
        let mut plant = self.plant.lock();
        let before = plant.snapshot();
        let result = act(&mut plant);
        let after = plant.snapshot();
        (before, after, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Loop;
    use crate::faults::{Fault, FaultChange, FaultTarget, ProcessFault, SensorFault};
    use crate::sensors::Sensor;
    use fictionet::events::float;
    use fictionet_observe::Memory;

    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}

    /// Run options that keep the run's facts in `memory`.
    fn options(memory: &Arc<Memory>) -> fictionet::RunOptions {
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(memory.clone())
    }

    fn fault(change: FaultChange, expected_revision: u64) -> FaultCommand {
        FaultCommand {
            change,
            expected_revision,
        }
    }

    fn stuck_hot_leg(value: i16) -> FaultChange {
        FaultChange::Inject(Fault::Sensor {
            sensor: Sensor::HotLeg(Loop::A),
            kind: SensorFault::Stuck { value },
        })
    }

    #[test]
    fn driver_is_clone_send_and_sync() {
        assert_clone_send_sync::<Driver>();
    }

    #[test]
    fn advancing_matches_a_plain_plant() {
        let config = Config::default();
        let d = Driver::new(config.clone());
        d.advance_to(&(), 5000);

        let mut p = Plant::new(config);
        p.advance(5000);

        assert_eq!(d.snapshot().at_ms, 5000);
        assert_eq!(d.snapshot(), p.snapshot());
    }

    #[test]
    fn clones_and_the_shared_plant_see_the_same_state() {
        let d = Driver::new(Config::default());
        let clone = d.clone();
        let shared = d.plant();

        d.advance_to(&(), 1000);
        assert_eq!(clone.snapshot().at_ms, 1000);
        // Bind the guarded snapshot first: `d.snapshot()` locks the same plant.
        let shared_snapshot = shared.lock().snapshot();
        assert_eq!(shared_snapshot, d.snapshot());

        let command: Command = serde_json::from_str(r#"{"rod_demand":{"tenths_percent":480}}"#)
            .expect("the command JSON is valid");
        shared
            .lock()
            .apply(command)
            .expect("the rod demand is in range");
        assert_eq!(d.snapshot().operator_actions, 1);
        assert_eq!(clone.snapshot().operator_actions, 1);
    }

    #[test]
    fn a_fault_start_and_clear_are_logged_with_their_target() -> fictionet::Result {
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Config::default());
        fictionet::block_on(fictionet::lab(options(&memory), move |cx| async move {
            driver.advance_to(&cx, 500);
            driver
                .apply_fault(&cx, fault(stuck_hot_leg(3000), 0))
                .expect("the fault is accepted");
            driver.advance_to(&cx, 1_000);
            driver
                .apply_fault(
                    &cx,
                    fault(
                        FaultChange::Clear(FaultTarget::Sensor(Sensor::HotLeg(Loop::A))),
                        1,
                    ),
                )
                .expect("the clear is accepted");
            Ok(())
        }))?;

        let faults = memory.checked_of("plant", "fault")?;
        assert_eq!(faults.len(), 2);
        assert_eq!(faults[0].str("change"), Some("inject"));
        assert_eq!(faults[0].str("target"), Some("hot_leg_a"));
        assert_eq!(faults[0].u64("last_fault_start_ms"), Some(500));
        assert_eq!(faults[0].u64("at_ms"), Some(500));
        assert_eq!(faults[1].str("change"), Some("clear"));
        assert_eq!(faults[1].str("target"), Some("hot_leg_a"));
        assert_eq!(faults[1].u64("at_ms"), Some(1_000));
        Ok(())
    }

    #[test]
    fn a_manual_trip_applied_here_is_logged_as_a_trip_not_an_action() -> fictionet::Result {
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Config::default());
        fictionet::block_on(fictionet::lab(options(&memory), move |cx| async move {
            driver.advance_to(&cx, 1_000);
            driver
                .apply(&cx, Command::ManualTrip)
                .expect("the manual trip is accepted");
            Ok(())
        }))?;

        let trips = memory.checked_of("plant", "trip")?;
        assert_eq!(trips.len(), 1);
        assert_eq!(trips[0].str("cause"), Some("manual"));
        assert_eq!(trips[0].u64("tripped_ms"), Some(1_000));
        assert_eq!(trips[0].u64("at_ms"), Some(1_000));
        // The caller logs the action with its source. This method does not.
        assert!(memory.checked_of("plant", "action")?.is_empty());
        Ok(())
    }

    #[test]
    fn a_trip_latched_by_advancing_is_logged_once() -> fictionet::Result {
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Config::default());
        let loss = fault(
            FaultChange::Inject(Fault::Process(ProcessFault::CondenserCoolingLoss)),
            0,
        );
        fictionet::block_on(fictionet::lab(options(&memory), move |cx| async move {
            driver
                .apply_fault(&cx, loss)
                .expect("the cooling loss is accepted");
            // The condenser passes 15 kPa within about 15 s at full power, which
            // trips the turbine and, above 20% power, the reactor.
            driver.advance_to(&cx, 30_000);
            assert!(driver.snapshot().truth.reactor.trip.is_some());
            Ok(())
        }))?;

        let trips = memory.checked_of("plant", "trip")?;
        assert_eq!(
            trips.len(),
            1,
            "the turbine trip is part of the reactor trip"
        );
        assert_eq!(trips[0].str("cause"), Some("turbine_trip"));
        let tripped = trips[0]
            .u64("tripped_ms")
            .ok_or_else(|| fictionet::Error::msg("the trip has its step"))?;
        assert!(tripped > 0 && tripped <= 30_000, "tripped at {tripped} ms");
        assert_eq!(trips[0].u64("at_ms"), Some(30_000));
        Ok(())
    }

    #[test]
    fn divergence_follows_a_sensor_fault_and_stops_when_it_clears() -> fictionet::Result {
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Config::default());
        fictionet::block_on(fictionet::lab(options(&memory), move |cx| async move {
            // No fault, no line.
            driver.advance_to(&cx, 1_000);
            // A stuck reading 25 C below the plant's hot leg.
            driver
                .apply_fault(&cx, fault(stuck_hot_leg(3000), 0))
                .expect("the fault is accepted");
            driver.advance_to(&cx, 3_000);
            driver
                .apply_fault(
                    &cx,
                    fault(
                        FaultChange::Clear(FaultTarget::Sensor(Sensor::HotLeg(Loop::A))),
                        1,
                    ),
                )
                .expect("the clear is accepted");
            driver.advance_to(&cx, 4_000);
            Ok(())
        }))?;

        let lines = memory.checked_of("plant", "divergence")?;
        assert_eq!(
            lines.len(),
            1,
            "one sample while the fault is active, none after"
        );
        assert_eq!(lines[0].str("point"), Some("hot_leg_a"));
        assert_eq!(lines[0].get("reported_value"), Some(&float(300.0)));
        assert_eq!(lines[0].u64("at_ms"), Some(3_000));
        let true_value = lines[0]
            .get("true_value")
            .and_then(|value| value.as_f64())
            .ok_or_else(|| fictionet::Error::msg("true_value is a number"))?;
        assert!(
            true_value - 300.0 > 20.0,
            "the plant's hot leg is near full power, 325 C, not 300 C: {true_value}"
        );
        Ok(())
    }
}
