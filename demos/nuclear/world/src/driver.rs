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

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use fictionet::sync::Mutex;

use crate::command::{Applied, Command, FaultCommand, Rejected};
use crate::facts::{self, Sink};
use crate::sensors::{SENSOR_COUNT, Sensor};
use crate::snapshot::PlantSnapshot;
use crate::{Config, Plant};

/// A cheaply cloneable, thread-safe handle to one plant. Clones share the plant.
#[derive(Clone)]
pub struct Driver {
    facts: facts::Observer,
    plant: Arc<Mutex<Plant>>,
    generation: Arc<AtomicU64>,
    divergence: Arc<Mutex<[Option<Peak>; SENSOR_COUNT]>>,
}

#[derive(Clone, Copy)]
struct Sample {
    at_ms: u64,
    truth: f64,
    reported: f64,
}

impl Sample {
    fn gap(self) -> f64 {
        (self.truth - self.reported).abs()
    }

    fn emit(self, sink: &impl Sink, sensor: Sensor, phase: facts::Phase) {
        facts::divergence(sink, sensor, self.truth, self.reported, self.at_ms, phase);
    }
}

#[derive(Clone, Copy)]
struct Peak {
    sample: Sample,
    grown: bool,
    emitted: bool,
}

fn track(sink: &impl Sink, peaks: &mut [Option<Peak>; SENSOR_COUNT], after: &PlantSnapshot) {
    for channel in &after.readings {
        let sensor = channel.sensor;
        let sample = Sample {
            at_ms: after.at_ms,
            truth: facts::true_value_of(after, sensor),
            reported: channel.reading.value,
        };
        let slot = &mut peaks[sensor.index()];
        if channel.fault.is_some() {
            if let Some(peak) = slot {
                if !peak.emitted && sample.at_ms > peak.sample.at_ms {
                    if sample.gap() > peak.sample.gap() {
                        peak.sample = sample;
                        peak.grown = true;
                    } else if peak.grown {
                        peak.sample.emit(sink, sensor, facts::Phase::Peak);
                        peak.emitted = true;
                    }
                }
            } else {
                sample.emit(sink, sensor, facts::Phase::Start);
                *slot = Some(Peak {
                    sample,
                    grown: false,
                    emitted: false,
                });
            }
        } else if let Some(peak) = slot.take() {
            if !peak.emitted {
                peak.sample.emit(sink, sensor, facts::Phase::Peak);
            }
            sample.emit(sink, sensor, facts::Phase::Clear);
        }
    }
}

impl Driver {
    /// Starts a plant built from `config` at plant time zero.
    pub fn new(config: Config) -> Driver {
        Driver {
            facts: facts::Observer::default(),
            plant: Arc::new(Mutex::new(Plant::new(config))),
            generation: Arc::new(AtomicU64::new(0)),
            divergence: Arc::new(Mutex::new([None; SENSOR_COUNT])),
        }
    }

    /// Receives this world's typed facts from the clock and controller services.
    pub fn observe(mut self, receive: impl Fn(facts::Fact) + Send + Sync + 'static) -> Self {
        self.facts = facts::Observer::new(receive);
        self
    }

    /// The observation sink shared by this driver's services.
    pub fn facts(&self) -> facts::Observer {
        self.facts.clone()
    }

    /// Replace the plant without replacing any shared handles.
    pub fn reset(&self, config: Config) {
        let mut plant = self.plant.lock();
        *plant = Plant::new(config);
        *self.divergence.lock() = [None; SENSOR_COUNT];
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The number of resets seen by every clone.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Returns a clone of the shared plant, so other services can use it.
    pub fn plant(&self) -> Arc<Mutex<Plant>> {
        Arc::clone(&self.plant)
    }

    /// Advances the plant to the absolute time `to_ms`. Only whole 50 ms steps
    /// run, and an earlier target does nothing. Tracks each sensor fault at
    /// each step and delivers its start, peak, and clear values.
    pub fn advance_to(&self, sink: &impl Sink, to_ms: u64) {
        let held = facts::Held::new(sink);
        let (before, after) = {
            let mut plant = self.plant.lock();
            let mut peaks = self.divergence.lock();
            let before = plant.snapshot();
            let mut after = before.clone();
            while to_ms.saturating_sub(after.at_ms) >= crate::plant::STEP_MS {
                plant.advance(after.at_ms + crate::plant::STEP_MS);
                after = plant.snapshot();
                track(&held, &mut peaks, &after);
                if before.end.is_none() && after.end.is_some() {
                    break;
                }
            }
            (before, after)
        };
        facts::changes(sink, &before, &after);
        held.release();
    }

    /// Returns the plant's state at the current plant time.
    pub fn snapshot(&self) -> PlantSnapshot {
        self.plant.lock().snapshot()
    }

    /// Applies an operator command at the current plant time. Delivers the trip
    /// or the first action that the command makes. It does not deliver the
    /// action itself, which the caller logs with its source.
    pub fn apply(&self, sink: &impl Sink, command: Command) -> Result<Applied, Rejected> {
        let (before, after, result) = self.act(sink, |plant| plant.apply(command));
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
        let held = facts::Held::new(sink);
        let (_, after, result) = self.act(&held, |plant| plant.apply_fault(command));
        if result.is_ok() {
            facts::fault(sink, command.change, &after);
        }
        held.release();
        result
    }

    /// Runs `act` on the plant. Returns the snapshots before and after it, read
    /// under the same lock, and the result of `act`.
    fn act<T>(
        &self,
        sink: &impl Sink,
        act: impl FnOnce(&mut Plant) -> T,
    ) -> (PlantSnapshot, PlantSnapshot, T) {
        let held = facts::Held::new(sink);
        let mut plant = self.plant.lock();
        let before = plant.snapshot();
        let result = act(&mut plant);
        let after = plant.snapshot();
        track(&held, &mut self.divergence.lock(), &after);
        drop(plant);
        held.release();
        (before, after, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Loop;
    use crate::faults::{Fault, FaultChange, FaultTarget, ProcessFault, SensorFault};
    use crate::sensors::Sensor;

    use crate::facts::tests::{Memory, observations, observer};
    use crate::facts::{Detail, Phase};
    use crate::protection::TripCause;
    use crate::stages::FailureCause;

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
    fn stages_and_end_follow_the_log_with_operator_context() -> fictionet::Result {
        use crate::scenarios::Scenario;
        use crate::stages::Stage;
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Scenario::LoopBUnattended.config());
        let observed = driver.clone();
        let sink = observer(&memory);
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |_cx| async move {
                driver.advance_to(&sink, 1_800_000);
                driver.apply(&sink, Command::AcknowledgeAlarms).unwrap();
                driver.advance_to(&sink, 24 * 3_600_000);
                let ended = driver.snapshot();
                assert_eq!(ended.at_ms, ended.end.unwrap().at_ms);
                driver.advance_to(&sink, ended.at_ms + 50);
                assert_eq!(driver.snapshot().at_ms, ended.at_ms + 50);
                Ok(())
            },
        ))?;
        let snapshot = observed.snapshot();
        let mut expected = Stage::ALL
            .into_iter()
            .filter_map(|stage| snapshot.stages[stage.index()].map(|at| (stage, at)))
            .collect::<Vec<_>>();
        expected.sort_by_key(|(stage, at)| (*at, stage.index()));
        let stages = observations(&memory, |detail| matches!(detail, Detail::Stage { .. }));
        assert_eq!(stages.len(), expected.len());
        for (fact, (stage, at)) in stages.iter().zip(expected) {
            assert!(
                matches!(fact.detail, Detail::Stage { stage: observed, .. } if observed == stage)
            );
            assert_eq!(fact.at_ms, at);
            assert_eq!(fact.time.as_str(), facts::time(at).as_str());
            assert!(!fact.summary.contains('_'));
        }
        let boiling = stages
            .iter()
            .find(|fact| {
                matches!(
                    fact.detail,
                    Detail::Stage {
                        stage: Stage::Boiling,
                        ..
                    }
                )
            })
            .unwrap();
        assert!(matches!(
            boiling.detail,
            Detail::Stage {
                last_command: None,
                last_command_ms: None,
                operator_actions: 0,
                ..
            }
        ));
        let uncovered = stages
            .iter()
            .find(|fact| {
                matches!(
                    fact.detail,
                    Detail::Stage {
                        stage: Stage::CoreUncovered,
                        ..
                    }
                )
            })
            .unwrap();
        assert!(matches!(
            uncovered.detail,
            Detail::Stage {
                operator_actions: 1,
                last_command: Some(Command::AcknowledgeAlarms),
                last_command_ms: Some(1_800_000),
                ..
            }
        ));
        let ends = observations(&memory, |detail| matches!(detail, Detail::End { .. }));
        assert_eq!(ends.len(), 1);
        assert!(matches!(
            ends[0].detail,
            Detail::End {
                stage: Stage::ContainmentFailure,
                cause: Some(FailureCause::HydrogenBurn),
                operator_actions: 1
            }
        ));
        assert_eq!(ends[0].at_ms, snapshot.end.unwrap().at_ms);
        Ok(())
    }

    #[test]
    fn reset_keeps_handles_and_clears_divergence() {
        let driver = Driver::new(Config::default());
        let shared = driver.plant();
        let clone = driver.clone();
        driver
            .apply_fault(&(), fault(stuck_hot_leg(3000), 0))
            .unwrap();
        driver.advance_to(&(), 1_000);
        assert!(driver.divergence.lock().iter().any(Option::is_some));
        driver.reset(crate::scenarios::Scenario::SteamLineBreak.config());
        assert_eq!(clone.generation(), 1);
        assert!(Arc::ptr_eq(&shared, &driver.plant()));
        assert_eq!(
            clone.snapshot(),
            Plant::new(crate::scenarios::Scenario::SteamLineBreak.config()).snapshot()
        );
        assert!(driver.divergence.lock().iter().all(Option::is_none));
    }

    #[test]
    fn each_tick_reaches_its_target_or_stops_at_the_end() {
        for scenario in crate::scenarios::Scenario::ALL {
            let driver = Driver::new(scenario.config());
            let mut total = std::time::Duration::ZERO;
            let mut maximum = std::time::Duration::ZERO;
            for _ in 0..120 {
                let target = driver.snapshot().at_ms + 30_000;
                let started = std::time::Instant::now();
                driver.advance_to(&(), target);
                let elapsed = started.elapsed();
                total += elapsed;
                maximum = maximum.max(elapsed);
                let snapshot = driver.snapshot();
                assert!(
                    snapshot.at_ms == target
                        || snapshot.end.is_some_and(|end| end.at_ms == snapshot.at_ms)
                );
            }
            println!(
                "{scenario:?}: 120 ticks, mean {:.3} ms, max {:.3} ms",
                total.as_secs_f64() * 1_000.0 / 120.0,
                maximum.as_secs_f64() * 1_000.0
            );
        }
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
        let sink = observer(&memory);
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |_cx| async move {
                driver.advance_to(&sink, 500);
                driver
                    .apply_fault(&sink, fault(stuck_hot_leg(3000), 0))
                    .expect("the fault is accepted");
                driver.advance_to(&sink, 1_000);
                driver
                    .apply_fault(
                        &sink,
                        fault(
                            FaultChange::Clear(FaultTarget::Sensor(Sensor::HotLeg(Loop::A))),
                            1,
                        ),
                    )
                    .expect("the clear is accepted");
                Ok(())
            },
        ))?;

        let faults = observations(&memory, |detail| matches!(detail, Detail::Fault { .. }));
        assert_eq!(faults.len(), 2);
        assert!(
            matches!(faults[0].detail, Detail::Fault { change, last_fault_start_ms: Some(500) } if change == stuck_hot_leg(3000))
        );
        assert_eq!(faults[0].at_ms, 500);
        assert!(matches!(
            faults[1].detail,
            Detail::Fault {
                change: FaultChange::Clear(FaultTarget::Sensor(Sensor::HotLeg(Loop::A))),
                ..
            }
        ));
        assert_eq!(faults[1].at_ms, 1_000);
        Ok(())
    }

    #[test]
    fn a_manual_trip_applied_here_is_logged_as_a_trip_not_an_action() -> fictionet::Result {
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Config::default());
        let sink = observer(&memory);
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |_cx| async move {
                driver.advance_to(&sink, 1_000);
                driver
                    .apply(&sink, Command::ManualTrip)
                    .expect("the manual trip is accepted");
                Ok(())
            },
        ))?;

        let trips = observations(&memory, |detail| matches!(detail, Detail::Trip { .. }));
        assert_eq!(trips.len(), 1);
        assert!(matches!(
            trips[0].detail,
            Detail::Trip {
                cause: TripCause::Manual,
                tripped_ms: Some(1_000)
            }
        ));
        assert_eq!(trips[0].at_ms, 1_000);
        // The caller logs the action with its source. This method does not.
        assert!(observations(&memory, |detail| matches!(detail, Detail::Action { .. })).is_empty());
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
        let sink = observer(&memory);
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |_cx| async move {
                driver
                    .apply_fault(&sink, loss)
                    .expect("the cooling loss is accepted");
                // The condenser passes 15 kPa within about 15 s at full power, which
                // trips the turbine and, above 20% power, the reactor.
                driver.advance_to(&sink, 30_000);
                assert!(driver.snapshot().truth.reactor.trip.is_some());
                Ok(())
            },
        ))?;

        let trips = observations(&memory, |detail| matches!(detail, Detail::Trip { .. }));
        assert_eq!(
            trips.len(),
            1,
            "the turbine trip is part of the reactor trip"
        );
        let Detail::Trip {
            cause,
            tripped_ms: Some(tripped),
        } = trips[0].detail
        else {
            panic!("expected a reactor trip with its step");
        };
        assert_eq!(cause, TripCause::TurbineTrip);
        assert!(tripped > 0 && tripped <= 30_000, "tripped at {tripped} ms");
        assert_eq!(trips[0].at_ms, 30_000);
        Ok(())
    }

    #[test]
    fn divergence_marks_the_first_peak_or_defers_it_until_clear() -> fictionet::Result {
        for gaps in [[1.0, 2.0, 2.0, 4.0], [1.0, 2.0, 3.0, 4.0]] {
            let memory = Arc::new(Memory::default());
            let observed = memory.clone();
            let sink = observer(&memory);
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(1),
                move |_cx| async move {
                    let mut peaks = [None; SENSOR_COUNT];
                    let mut snapshot = Plant::new(Config::default()).snapshot();
                    let sensor = Sensor::HotLeg(Loop::A);
                    snapshot.readings[sensor.index()].fault =
                        Some(SensorFault::Stuck { value: 3000 });
                    snapshot.readings[sensor.index()].reading.value = 300.0;
                    for (step, gap) in gaps.into_iter().enumerate() {
                        snapshot.at_ms = step as u64 * 50;
                        snapshot.truth.primary.loops[0].hot_leg_c = 300.0 + gap;
                        track(&sink, &mut peaks, &snapshot);
                    }
                    let before_clear = observations(&observed, |detail| {
                        matches!(detail, Detail::Divergence { .. })
                    });
                    assert_eq!(before_clear.len(), if gaps[2] == 2.0 { 2 } else { 1 });
                    snapshot.at_ms = 200;
                    snapshot.readings[sensor.index()].fault = None;
                    track(&sink, &mut peaks, &snapshot);
                    snapshot.at_ms = 250;
                    track(&sink, &mut peaks, &snapshot);
                    Ok(())
                },
            ))?;
            let lines = observations(&memory, |detail| {
                matches!(detail, Detail::Divergence { .. })
            });
            assert_eq!(lines.len(), 3);
            assert!(matches!(
                lines[0].detail,
                Detail::Divergence {
                    phase: Phase::Start,
                    ..
                }
            ));
            assert!(matches!(
                lines[1].detail,
                Detail::Divergence {
                    phase: Phase::Peak,
                    ..
                }
            ));
            assert!(matches!(
                lines[2].detail,
                Detail::Divergence {
                    phase: Phase::Clear,
                    ..
                }
            ));
            let (peak_time, peak_value) = if gaps[2] == 2.0 {
                (50, 302.0)
            } else {
                (150, 304.0)
            };
            assert_eq!(lines[1].at_ms, peak_time);
            let Detail::Divergence {
                true_value,
                reported_value,
                ..
            } = lines[1].detail
            else {
                panic!("expected a sensor divergence");
            };
            assert_eq!(true_value, peak_value);
            assert_eq!(reported_value, 300.0);
            assert_eq!(lines[2].at_ms, 200);
        }
        Ok(())
    }

    #[test]
    fn divergence_follows_a_sensor_fault_and_stops_when_it_clears() -> fictionet::Result {
        let memory = Arc::new(Memory::default());
        let driver = Driver::new(Config::default());
        let sink = observer(&memory);
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |_cx| async move {
                // No fault, no line.
                driver.advance_to(&sink, 1_000);
                // A stuck reading 25 C below the plant's hot leg.
                driver
                    .apply_fault(&sink, fault(stuck_hot_leg(3000), 0))
                    .expect("the fault is accepted");
                driver.advance_to(&sink, 3_000);
                driver
                    .apply_fault(
                        &sink,
                        fault(
                            FaultChange::Clear(FaultTarget::Sensor(Sensor::HotLeg(Loop::A))),
                            1,
                        ),
                    )
                    .expect("the clear is accepted");
                driver.advance_to(&sink, 4_000);
                Ok(())
            },
        ))?;

        let lines = observations(&memory, |detail| {
            matches!(detail, Detail::Divergence { .. })
        });
        assert_eq!(lines.len(), 3, "one start, peak, and clear, none after");
        assert!(matches!(
            lines[0].detail,
            Detail::Divergence {
                point: Sensor::HotLeg(Loop::A),
                ..
            }
        ));
        for (line, expected) in lines.iter().zip([Phase::Start, Phase::Peak, Phase::Clear]) {
            assert!(matches!(line.detail, Detail::Divergence { phase, .. } if phase == expected));
        }
        assert_eq!(lines[0].at_ms, 1_000);
        assert_eq!(lines[2].at_ms, 3_000);
        assert_eq!(lines[2].time.as_str(), "0:03.0");
        let Detail::Divergence {
            true_value,
            reported_value,
            ..
        } = lines[1].detail
        else {
            panic!("expected a sensor divergence");
        };
        assert_eq!(reported_value, 300.0);
        assert!(lines[1].at_ms >= 1_000);
        assert!(lines[1].at_ms <= 3_000);
        assert!(
            true_value - 300.0 > 20.0,
            "the plant's hot leg is near full power, 325 C, not 300 C: {true_value}"
        );
        Ok(())
    }
}
