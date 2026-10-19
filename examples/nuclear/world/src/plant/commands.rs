//! Command validation and bounded fault mutation at the current plant time.
use super::*;

impl Plant {
    fn reject(&self, reason: Rejection) -> Rejected {
        Rejected {
            reason,
            revision: self.revision,
        }
    }
    fn applied(&self) -> Applied {
        Applied {
            revision: self.revision,
            at_ms: self.at_ms,
        }
    }

    pub fn apply(&mut self, command: Command) -> Result<Applied, Rejected> {
        self.operator_command(command)
            .map_err(|reason| self.reject(reason))?;
        self.operator_actions = self.operator_actions.saturating_add(1);
        if self.first_action_after_fault_ms.is_none() {
            self.first_action_after_fault_ms = self.last_fault_start_ms.map(|at| self.at_ms - at);
        }
        Ok(self.applied())
    }

    fn operator_command(&mut self, command: Command) -> Result<(), Rejection> {
        match command {
            Command::RodDemand { tenths_percent } => {
                if tenths_percent > 1000 {
                    return Err(Rejection::OutOfRange);
                }
                if self.state.reactor.trip.is_some() && tenths_percent > 0 {
                    return Err(Rejection::Tripped);
                }
                self.state.reactor.rod_demand_percent = f64::from(tenths_percent) / 10.0;
            }
            Command::ManualTrip => {
                if self.state.reactor.trip.is_some() {
                    return Err(Rejection::AlreadyActive);
                }
                self.trip(TripCause::Manual);
            }
            Command::ResetTrip => {
                if self.state.reactor.trip.is_none() && !self.state.secondary.turbine_tripped {
                    return Err(Rejection::NotActive);
                }
                if self.inputs().cause().is_some()
                    || self.state.secondary.condenser_pressure_kpa >= LOW_VACUUM_KPA
                {
                    return Err(Rejection::TripConditionPresent);
                }
                self.state.reactor.trip = None;
                self.state.reactor.shutdown_rod_percent_inserted = 0.0;
                self.state.reactor.rod_demand_percent = self.state.reactor.control_rod_percent;
                self.state.secondary.turbine_tripped = false;
                self.turbine_demand = 0.0;
                self.revision = self.revision.saturating_add(1);
            }
            Command::Pump { pump, running } => {
                let fault = match pump {
                    Pump::Coolant(l) => Some(ProcessFault::CoolantPumpTrip { pump: l }),
                    Pump::MainFeed(l) => Some(ProcessFault::FeedPumpTrip { pump: l }),
                    _ => None,
                };
                if running && fault.is_some_and(|f| self.faults.has(f)) {
                    return Err(Rejection::Faulted);
                }
                match pump {
                    Pump::Coolant(l) => self.state.primary.loops[l.index()].pump_running = running,
                    Pump::MainFeed(l) => {
                        self.state.secondary.feed_pumps_running[l.index()] = running
                    }
                    Pump::AuxiliaryFeed => self.state.secondary.auxiliary_feed_running = running,
                    Pump::CirculatingWater => {
                        self.state.secondary.circulating_water_running = running
                    }
                }
            }
            Command::ValveDemand { valve, permille } => {
                if permille > 1000 {
                    return Err(Rejection::OutOfRange);
                }
                let demand = f64::from(permille) / 10.0;
                match valve {
                    Valve::Feed(l) => {
                        if self.faults.has(ProcessFault::FeedValveStuck { line: l }) {
                            return Err(Rejection::Faulted);
                        }
                        if self.state.controllers.feed_level[l.index()] == Mode::Automatic {
                            return Err(Rejection::WrongMode);
                        }
                        self.feed_demand[l.index()] = demand;
                    }
                    Valve::Turbine => {
                        if self.state.secondary.turbine_tripped && permille > 0 {
                            return Err(Rejection::Tripped);
                        }
                        self.turbine_demand = demand;
                    }
                    Valve::SteamDump => {
                        if self.state.controllers.steam_dump == Mode::Automatic {
                            return Err(Rejection::WrongMode);
                        }
                        self.dump_demand = demand;
                    }
                    Valve::PressurizerSpray => {
                        if self.state.controllers.pressurizer_pressure == Mode::Automatic {
                            return Err(Rejection::WrongMode);
                        }
                        self.spray_demand = demand;
                    }
                }
            }
            Command::Controller { controller, mode } => match controller {
                Controller::FeedLevel(l) => {
                    self.feed_demand[l.index()] =
                        self.state.secondary.loops[l.index()].feed_valve_percent;
                    self.state.controllers.feed_level[l.index()] = mode;
                }
                Controller::PressurizerPressure => {
                    self.spray_demand = self.state.primary.spray_percent;
                    self.heater_demand = self.state.primary.heaters_on;
                    self.state.controllers.pressurizer_pressure = mode;
                }
                Controller::SteamDump => {
                    self.dump_demand = self.state.secondary.steam_dump_percent;
                    self.state.controllers.steam_dump = mode;
                }
            },
            Command::Heaters { on } => {
                if self.state.controllers.pressurizer_pressure == Mode::Automatic {
                    return Err(Rejection::WrongMode);
                }
                self.heater_demand = on;
            }
            Command::AcknowledgeAlarms => {
                for alarm in &mut self.alarms {
                    if *alarm == AlarmState::Active {
                        *alarm = AlarmState::Acknowledged;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn apply_fault(&mut self, command: FaultCommand) -> Result<Applied, Rejected> {
        if command.expected_revision != self.revision {
            return Err(self.reject(Rejection::StaleRevision));
        }
        self.change_fault(command.change)
            .map_err(|reason| self.reject(reason))?;
        Ok(self.applied())
    }

    pub(super) fn change_fault(&mut self, change: FaultChange) -> Result<(), Rejection> {
        match change {
            FaultChange::Inject(fault) => {
                match fault {
                    Fault::Process(f) => {
                        let slot = &mut self.faults.process[f.index()];
                        if slot.is_some() {
                            return Err(Rejection::AlreadyActive);
                        }
                        *slot = Some(f);
                    }
                    Fault::Sensor { sensor, kind } => {
                        let slot = &mut self.faults.sensors[sensor.index()];
                        if slot.is_some() {
                            return Err(Rejection::AlreadyActive);
                        }
                        if let SensorFault::Stuck { value } = kind {
                            let spec = sensor.spec();
                            let v = f64::from(value) * spec.resolution;
                            if v < spec.min || v > spec.max {
                                return Err(Rejection::OutOfRange);
                            }
                        }
                        *slot = Some(kind);
                    }
                    Fault::TelemetryQuiet => {
                        if self.faults.telemetry_quiet {
                            return Err(Rejection::AlreadyActive);
                        }
                        self.faults.telemetry_quiet = true;
                    }
                }
                self.last_fault_start_ms = Some(self.at_ms);
                self.first_action_after_fault_ms = None;
            }
            FaultChange::Clear(target) => match target {
                FaultTarget::Process(f) => {
                    if self.faults.process[f.index()].take().is_none() {
                        return Err(Rejection::NotActive);
                    }
                }
                FaultTarget::Sensor(s) => {
                    if self.faults.sensors[s.index()].take().is_none() {
                        return Err(Rejection::NotActive);
                    }
                }
                FaultTarget::TelemetryQuiet => {
                    if !self.faults.telemetry_quiet {
                        return Err(Rejection::NotActive);
                    }
                    self.faults.telemetry_quiet = false;
                }
            },
            FaultChange::ClearAll => {
                if self.faults == Faults::default() {
                    return Err(Rejection::NotActive);
                }
                self.faults = Faults::default();
            }
        }
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}
