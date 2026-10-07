//! Scenarios: a timeline of changes to a world while it runs, and the
//! facts a grader expects or forbids in its events.
//!
//! A [`Scenario`] holds steps, each a time after the start and a function
//! that changes the world's shared state or its fault plans: at 120 s a PLC
//! starts reporting a cooled temperature while the process keeps heating; at
//! 200 s a router announces a more specific route; at 300 s a price feed
//! freezes for two seconds ([`FaultPlan`]). [`Scenario::run`] plays the
//! timeline as a task on the run's clock.
//!
//! A scenario also says what the run's [events](crate::events) should and
//! should not hold: [`expect`](Scenario::expect) and
//! [`forbid`](Scenario::forbid) name a fact and the events that show it.
//! During the run or after it, [`Checks::grade`] counts them in the events,
//! such as every event the run's log holds ([`EventLog::all`]). Every run
//! keeps its events, so grading needs nothing set up first.
//!
//! [`EventLog::all`]: crate::events::EventLog::all
//!
//! ```
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicBool, Ordering};
//! use std::time::Duration;
//! use fictionet::events::{Event, Level};
//! use fictionet::stdlib::scenario::Scenario;
//!
//! struct Plant { spoofed: AtomicBool }
//! let scenario = Scenario::new()
//!     .at(Duration::from_secs(120), |plant: &Plant, _fcx| plant.spoofed.store(true, Ordering::SeqCst))
//!     .expect("the operator read the temperature", |e| e.is("modbus", "read_input"))
//!     .forbid("the operator kept the pump running", |e| e.is("modbus", "write_register") && e.level == Level::Alarm);
//! let checks = scenario.checks();
//! let log = std::sync::Arc::new(std::sync::Mutex::new(None));
//! let kept = log.clone();
//! # fictionet::block_on(fictionet::run(move |fcx| async move {
//! *kept.lock().unwrap() = Some(fcx.events());
//! let _timeline = scenario.run(&fcx, Arc::new(Plant { spoofed: AtomicBool::new(false) }));
//! fcx.record(Event::new("modbus", "read_input").field("register", 30001u32));
//! # fcx.cancel(); // End the example's world without waiting two minutes.
//! # Ok(()) }))?;
//! // The log is still there after the run.
//! let report = checks.grade(&log.lock().unwrap().take().unwrap().all());
//! assert!(report.passed());
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! Time is the run's clock (`Cx::now`), and fault plans take an explicit
//! seed, so a scenario repeats as far as the run's timing does.

use std::sync::Arc;
use std::time::Duration;

use fictionet::events::Event;
use fictionet::stdlib::serve::{FaultPlan, Plan};
use fictionet::{Cx, Task};

/// What a step does: changes `W`, with the run's context at hand.
type Act<W> = Box<dyn FnOnce(&W, &Cx) + Send>;

/// Whether an event shows a fact.
type Pick = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

/// One step of a scenario.
pub struct Step<W> {
    /// When it happens, after the timeline starts.
    pub at: Duration,
    /// What it does.
    pub act: Act<W>,
}

/// A timeline of changes, and the facts a grader checks. See the
/// [module docs](self).
pub struct Scenario<W> {
    steps: Vec<Step<W>>,
    checks: Vec<Check>,
}

impl<W> Default for Scenario<W> {
    fn default() -> Scenario<W> {
        Scenario { steps: Vec::new(), checks: Vec::new() }
    }
}

impl<W: Send + Sync + 'static> Scenario<W> {
    /// An empty scenario.
    pub fn new() -> Scenario<W> {
        Scenario::default()
    }

    /// At `at` after the start, runs `act` on the shared world state.
    /// Steps at the same time run in the order they were added.
    pub fn at(mut self, at: Duration, act: impl FnOnce(&W, &Cx) + Send + 'static) -> Scenario<W> {
        self.steps.push(Step { at, act: Box::new(act) });
        self
    }

    /// At `at`, replaces the rules of `faults` with `plan`, for every
    /// connection served with it.
    pub fn faults(self, at: Duration, faults: &FaultPlan, plan: Plan) -> Scenario<W> {
        let faults = faults.clone();
        self.at(at, move |_, _| faults.set(plan))
    }

    /// The events must hold at least one for which `pick` is true: `fact`
    /// names what it shows.
    pub fn expect(mut self, fact: &str, pick: impl Fn(&Event) -> bool + Send + Sync + 'static) -> Scenario<W> {
        self.checks.push(Check { fact: fact.to_owned(), expected: true, pick: Arc::new(pick) });
        self
    }

    /// The events must hold none for which `pick` is true.
    pub fn forbid(mut self, fact: &str, pick: impl Fn(&Event) -> bool + Send + Sync + 'static) -> Scenario<W> {
        self.checks.push(Check { fact: fact.to_owned(), expected: false, pick: Arc::new(pick) });
        self
    }

    /// The scenario's checks, to grade the events.
    pub fn checks(&self) -> Checks {
        Checks { checks: self.checks.clone() }
    }

    /// Plays the timeline as a task on `fcx`, against `world`. The task ends
    /// after the last step, or when the region is cancelled.
    pub fn run(self, fcx: &Cx, world: Arc<W>) -> Task {
        let mut steps = self.steps;
        // A stable sort keeps the order of steps at the same time.
        steps.sort_by_key(|s| s.at);
        fcx.spawn(move |fcx| async move {
            let start = fcx.now();
            for step in steps {
                fcx.sleep_until(start + step.at).await?;
                (step.act)(&world, &fcx);
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct Check {
    fact: String,
    expected: bool,
    pick: Pick,
}

/// The facts a scenario checks, separate from its timeline.
#[derive(Clone)]
pub struct Checks {
    checks: Vec<Check>,
}

/// One fact, graded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graded {
    /// What the fact is.
    pub fact: String,
    /// Whether the scenario expects it (`true`) or forbids it.
    pub expected: bool,
    /// How many events show it.
    pub count: usize,
    /// The sequence numbers of the first events that show it, at most 16.
    pub seqs: Vec<u64>,
}

impl Graded {
    /// Whether the events agree with the scenario on this fact.
    pub fn passed(&self) -> bool {
        (self.count > 0) == self.expected
    }
}

/// Every fact of a scenario, graded against one run's events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The facts, in the order the scenario named them.
    pub facts: Vec<Graded>,
    /// How many events the log had dropped before the ones graded, from
    /// their `events.dropped` events. A fact may hide in those, so a
    /// grader that needs every event writes them to a file
    /// ([`EventLog::to_file`](crate::events::EventLog::to_file)) and
    /// grades that instead.
    pub dropped: u64,
}

impl Report {
    /// Whether every fact passed.
    pub fn passed(&self) -> bool {
        self.facts.iter().all(Graded::passed)
    }

    /// The facts that did not pass.
    pub fn failures(&self) -> Vec<&Graded> {
        self.facts.iter().filter(|g| !g.passed()).collect()
    }
}

impl Checks {
    /// Counts each fact in `events`.
    pub fn grade(&self, events: &[Event]) -> Report {
        let facts = self
            .checks
            .iter()
            .map(|c| {
                let hits: Vec<u64> = events.iter().filter(|e| (c.pick)(e)).map(|e| e.seq).collect();
                Graded { fact: c.fact.clone(), expected: c.expected, count: hits.len(), seqs: hits.into_iter().take(16).collect() }
            })
            .collect();
        let dropped = events.iter().filter(|e| e.is("events", "dropped")).filter_map(|e| e.u64("count")).sum();
        Report { facts, dropped }
    }
}
