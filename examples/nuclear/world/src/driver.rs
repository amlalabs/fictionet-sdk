//! A shared handle to one plant.
//!
//! [`Driver`] owns a [`Plant`] behind a mutex, so a PLC service and the
//! network can use the same plant from different threads. It reads no clock
//! and does no I/O. The caller supplies the plant time to advance to.

use std::sync::Arc;

use fictionet::sync::Mutex;

use crate::command::{Applied, Command, FaultCommand, Rejected};
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
    /// run, and an earlier target does nothing.
    pub fn advance_to(&self, to_ms: u64) {
        self.plant.lock().advance(to_ms);
    }

    /// Returns the plant's state at the current plant time.
    pub fn snapshot(&self) -> PlantSnapshot {
        self.plant.lock().snapshot()
    }

    /// Applies an operator command at the current plant time.
    pub fn apply(&self, command: Command) -> Result<Applied, Rejected> {
        self.plant.lock().apply(command)
    }

    /// Applies a fault change at the current plant time.
    pub fn apply_fault(&self, command: FaultCommand) -> Result<Applied, Rejected> {
        self.plant.lock().apply_fault(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}

    #[test]
    fn driver_is_clone_send_and_sync() {
        assert_clone_send_sync::<Driver>();
    }

    #[test]
    fn advancing_matches_a_plain_plant() {
        let config = Config::default();
        let d = Driver::new(config.clone());
        d.advance_to(5000);

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

        d.advance_to(1000);
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
}
