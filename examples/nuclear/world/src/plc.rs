//! The Modbus/TCP server for one controller, as a [`serve::Service`].
//!
//! [`PlcService`] answers the controller's register map from [`registers`].
//! Reads take their values from a snapshot of the shared plant. Writes decode
//! to plant commands. An accepted write echoes the request, and a rejected one
//! answers with the exception that its reason maps to.
//!
//! An address outside the controller's block answers with illegal data address.
//! A function code the server does not implement answers with illegal function.
//! The unit identifier is not checked, since each controller is its own device.
//!
//! A write to several coils or registers applies all of its commands or none.
//! The commands run on a copy of the plant, which replaces the shared plant
//! only when every command is accepted.
//!
//! Switching a momentary coil (trip, reset, acknowledge) off decodes to no
//! command. Such a coil already reads as off, so the write is accepted and
//! changes nothing.

use std::convert::Infallible;
use std::sync::Arc;

use fictionet::stdlib::codec::{Frames, Wire};
use fictionet::stdlib::protocols::modbus::{Exception, Frame, Request, Response};
use fictionet::stdlib::services::serve::{self, Flow};
use fictionet::sync::Mutex;

use crate::Plant;
use crate::command::{Command, Rejection};
use crate::registers::{self, Plc};

/// One plant, shared by the connections of every controller.
pub type Shared = Arc<Mutex<Plant>>;

/// The Modbus/TCP server for one controller.
pub struct PlcService {
    /// The controller whose register map this connection serves.
    pub plc: Plc,
}

impl serve::Service for PlcService {
    type Decoder = Frames<Frame>;
    type State = Shared;
    type Error = Infallible;

    fn decoder(&self) -> Self::Decoder {
        Frames::new()
    }

    fn on_item(
        &mut self,
        frame: Frame,
        state: &Shared,
        driver: &mut serve::Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Infallible> {
        let pdu = self.answer(&frame, state);
        frame
            .reply(pdu)
            .write(driver.reply())
            .expect("a reply PDU is never empty and never longer than one Modbus PDU");
        Ok(Flow::Continue)
    }
}

impl PlcService {
    /// The reply PDU for one request frame.
    fn answer(&self, frame: &Frame, plant: &Shared) -> Vec<u8> {
        let function = frame.function().unwrap_or(0);
        let request = match Request::parse(&frame.pdu) {
            Ok(request) => request,
            Err(exception) => return exception.to_pdu(function),
        };
        match request {
            Request::ReadCoils { address, quantity } => {
                let block = registers::coils(self.plc, &plant.lock().snapshot());
                read_reply(&block, address, quantity, function, Response::Bits)
            }
            Request::ReadDiscreteInputs { address, quantity } => {
                let block = registers::discrete_inputs(self.plc, &plant.lock().snapshot());
                read_reply(&block, address, quantity, function, Response::Bits)
            }
            Request::ReadHoldingRegisters { address, quantity } => {
                let block = registers::holding_registers(self.plc, &plant.lock().snapshot());
                read_reply(&block, address, quantity, function, Response::Registers)
            }
            Request::ReadInputRegisters { address, quantity } => {
                let block = registers::input_registers(self.plc, &plant.lock().snapshot());
                read_reply(&block, address, quantity, function, Response::Registers)
            }
            Request::WriteSingleCoil { address, value } => {
                let commands = self.coil_commands(plant, address, &[value]);
                write_reply(
                    plant,
                    commands,
                    function,
                    Response::WriteSingleCoil { address, value },
                )
            }
            Request::WriteMultipleCoils { address, values } => {
                let commands = self.coil_commands(plant, address, &values);
                let quantity = values.len() as u16;
                write_reply(
                    plant,
                    commands,
                    function,
                    Response::WriteMultiple { address, quantity },
                )
            }
            Request::WriteSingleRegister { address, value } => {
                let commands = self.register_commands(address, &[value]);
                write_reply(
                    plant,
                    commands,
                    function,
                    Response::WriteSingleRegister { address, value },
                )
            }
            Request::WriteMultipleRegisters { address, values } => {
                let commands = self.register_commands(address, &values);
                let quantity = values.len() as u16;
                write_reply(
                    plant,
                    commands,
                    function,
                    Response::WriteMultiple { address, quantity },
                )
            }
            Request::Other { .. } => Exception::IllegalFunction.to_pdu(function),
        }
    }

    /// The commands for writing `values` to the coils from `address`, or `None`
    /// when a coil lies outside the controller's block.
    fn coil_commands(&self, plant: &Shared, address: u16, values: &[bool]) -> Option<Vec<Command>> {
        let block = registers::coils(self.plc, &plant.lock().snapshot()).len();
        let mut commands = Vec::with_capacity(values.len());
        for (i, &on) in values.iter().enumerate() {
            // The request's range check keeps every coil address below 65536.
            let coil = address + i as u16;
            match registers::decode_coil_write(self.plc, coil, on) {
                Some(command) => commands.push(command),
                // A momentary coil switched off has no command. It reads as off already.
                None if usize::from(coil) < block => {}
                None => return None,
            }
        }
        Some(commands)
    }

    /// The commands for writing `values` to the holding registers from
    /// `address`, or `None` when a register lies outside the controller's block.
    fn register_commands(&self, address: u16, values: &[u16]) -> Option<Vec<Command>> {
        values
            .iter()
            .enumerate()
            // The request's range check keeps every register address below 65536.
            .map(|(i, &value)| {
                registers::decode_register_write(self.plc, address + i as u16, value)
            })
            .collect()
    }
}

/// The reply to a read of `quantity` values from `address`, or illegal data
/// address when the block does not hold all of them.
fn read_reply<T: Clone>(
    block: &[T],
    address: u16,
    quantity: u16,
    function: u8,
    respond: fn(Vec<T>) -> Response,
) -> Vec<u8> {
    let start = usize::from(address);
    match block.get(start..start + usize::from(quantity)) {
        Some(values) => reply_pdu(respond(values.to_vec()), function),
        None => Exception::IllegalDataAddress.to_pdu(function),
    }
}

/// The reply to a write with `commands`. No commands means the write named an
/// address outside the block. Otherwise the commands apply in order, all or
/// none, and the reply echoes the write or gives the exception of the rejection.
fn write_reply(
    plant: &Shared,
    commands: Option<Vec<Command>>,
    function: u8,
    echo: Response,
) -> Vec<u8> {
    let Some(commands) = commands else {
        return Exception::IllegalDataAddress.to_pdu(function);
    };
    match apply_commands(plant, &commands) {
        Ok(()) => reply_pdu(echo, function),
        Err(exception) => exception.to_pdu(function),
    }
}

/// Applies `commands` to the shared plant, in order, as one step. They run on a
/// copy under the plant's lock, and the copy replaces the plant only when every
/// command is accepted. A rejection returns its exception and leaves the plant
/// as it was.
fn apply_commands(plant: &Shared, commands: &[Command]) -> Result<(), Exception> {
    let mut guard = plant.lock();
    let mut trial = (*guard).clone();
    for &command in commands {
        trial
            .apply(command)
            .map_err(|rejected| exception_for(rejected.reason))?;
    }
    *guard = trial;
    Ok(())
}

/// The Modbus exception that answers a rejected command. A value the plant
/// cannot take is an illegal data value. A command the plant's state refuses
/// is a server device failure.
fn exception_for(reason: Rejection) -> Exception {
    match reason {
        Rejection::OutOfRange | Rejection::WrongMode => Exception::IllegalDataValue,
        Rejection::Faulted
        | Rejection::Tripped
        | Rejection::AlreadyActive
        | Rejection::NotActive
        | Rejection::TripConditionPresent
        | Rejection::StaleRevision => Exception::ServerDeviceFailure,
    }
}

/// Encodes `response` as the reply to `function`. A response the codec refuses
/// becomes a server device failure, so every request gets a reply.
fn reply_pdu(response: Response, function: u8) -> Vec<u8> {
    response
        .to_pdu(function)
        .unwrap_or_else(|_| Exception::ServerDeviceFailure.to_pdu(function))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::error::Error;

    const TRANSACTION: u16 = 7;

    fn plant() -> Shared {
        Arc::new(Mutex::new(Plant::new(Config::default())))
    }

    fn harness(plc: Plc, plant: &Shared) -> serve::Harness<PlcService> {
        serve::Harness::new(
            fictionet::Seed::from_u64(0),
            PlcService { plc },
            plant.clone(),
        )
    }

    /// Sends one request frame through the harness and reads back the reply.
    fn exchange(
        h: &mut serve::Harness<PlcService>,
        request: &Request,
    ) -> Result<Response, Box<dyn Error>> {
        let pdu = request.to_pdu()?;
        let bytes = Frame {
            transaction: TRANSACTION,
            unit: 1,
            pdu,
        }
        .to_bytes()?;
        let reply = h.push(&bytes)?;
        let (frame, used) = Frame::parse_prefix(&reply)?.ok_or("the reply is not a whole frame")?;
        assert_eq!(used, reply.len(), "one request, one reply");
        assert_eq!(frame.transaction, TRANSACTION);
        let (function, response) = Response::parse(&frame.pdu)?;
        assert_eq!(function, request.function());
        Ok(response)
    }

    fn exception_code(response: &Response) -> Option<u8> {
        match response {
            Response::Exception(exception) => Some(exception.code()),
            _ => None,
        }
    }

    /// The first `quantity` bits of a read reply. A reply carries whole bytes,
    /// so its bits can run past the quantity asked for.
    fn bits_of(response: Response, quantity: usize) -> Vec<bool> {
        match response {
            Response::Bits(bits) => bits[..quantity].to_vec(),
            other => panic!("expected bits, got {other:?}"),
        }
    }

    #[test]
    fn input_register_read_returns_the_scaled_count() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Rcs1, &plant);
        let response = exchange(
            &mut h,
            &Request::ReadInputRegisters {
                address: 4,
                quantity: 1,
            },
        )?;
        let expected = registers::input_registers(Plc::Rcs1, &plant.lock().snapshot());
        assert_eq!(expected[4], 1550, "pressurizer pressure at 15.50 MPa");
        assert_eq!(response, Response::Registers(vec![expected[4]]));
        Ok(())
    }

    #[test]
    fn input_register_read_past_the_block_is_an_illegal_data_address() -> Result<(), Box<dyn Error>>
    {
        let plant = plant();
        let mut h = harness(Plc::Rcs1, &plant);
        let response = exchange(
            &mut h,
            &Request::ReadInputRegisters {
                address: 50,
                quantity: 1,
            },
        )?;
        assert_eq!(
            exception_code(&response),
            Some(Exception::IllegalDataAddress.code())
        );
        Ok(())
    }

    #[test]
    fn rod_write_applies_to_the_plant_and_reads_back() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Rps1, &plant);
        let echo = exchange(
            &mut h,
            &Request::WriteSingleRegister {
                address: 0,
                value: 480,
            },
        )?;
        assert_eq!(
            echo,
            Response::WriteSingleRegister {
                address: 0,
                value: 480
            }
        );
        let read = exchange(
            &mut h,
            &Request::ReadHoldingRegisters {
                address: 0,
                quantity: 1,
            },
        )?;
        assert_eq!(read, Response::Registers(vec![480]));
        plant.lock().advance(1_000);
        let snapshot = plant.lock().snapshot();
        assert_eq!(snapshot.truth.reactor.rod_demand_percent, 48.0);
        assert_eq!(snapshot.operator_actions, 1);
        Ok(())
    }

    #[test]
    fn feed_valve_write_in_automatic_is_an_illegal_data_value() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Bop1, &plant);
        let response = exchange(
            &mut h,
            &Request::WriteSingleRegister {
                address: 0,
                value: 500,
            },
        )?;
        assert_eq!(
            exception_code(&response),
            Some(Exception::IllegalDataValue.code())
        );
        assert_eq!(
            plant.lock().snapshot().operator_actions,
            0,
            "a rejected write is no operator action"
        );
        Ok(())
    }

    #[test]
    fn coil_and_discrete_reads_return_their_blocks() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut rcs = harness(Plc::Rcs1, &plant);
        // Full power starts with both coolant pumps, the heaters and the pressurizer controller on.
        let coils = exchange(
            &mut rcs,
            &Request::ReadCoils {
                address: 0,
                quantity: 4,
            },
        )?;
        assert_eq!(bits_of(coils, 4), vec![true; 4]);
        let past = exchange(
            &mut rcs,
            &Request::ReadCoils {
                address: 2,
                quantity: 3,
            },
        )?;
        assert_eq!(
            exception_code(&past),
            Some(Exception::IllegalDataAddress.code()),
            "a read that starts inside the block but runs past it is illegal"
        );

        let mut bop = harness(Plc::Bop1, &plant);
        let inputs = exchange(
            &mut bop,
            &Request::ReadDiscreteInputs {
                address: 0,
                quantity: 6,
            },
        )?;
        // Both feed pumps and circulating water run. The auxiliary feed pump is off.
        assert_eq!(
            bits_of(inputs, 6),
            vec![true, true, false, true, false, false]
        );
        Ok(())
    }

    #[test]
    fn momentary_coils_trip_the_reactor_and_switching_off_does_nothing()
    -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Rps1, &plant);
        let off = exchange(
            &mut h,
            &Request::WriteSingleCoil {
                address: 0,
                value: false,
            },
        )?;
        assert_eq!(
            off,
            Response::WriteSingleCoil {
                address: 0,
                value: false
            }
        );
        assert_eq!(plant.lock().snapshot().operator_actions, 0);

        let on = exchange(
            &mut h,
            &Request::WriteSingleCoil {
                address: 0,
                value: true,
            },
        )?;
        assert_eq!(
            on,
            Response::WriteSingleCoil {
                address: 0,
                value: true
            }
        );
        plant.lock().advance(1_000);
        assert!(plant.lock().snapshot().truth.reactor.trip.is_some());

        // With the trip active, a rod demand above zero is refused as a device failure.
        let response = exchange(
            &mut h,
            &Request::WriteSingleRegister {
                address: 0,
                value: 100,
            },
        )?;
        assert_eq!(
            exception_code(&response),
            Some(Exception::ServerDeviceFailure.code())
        );
        Ok(())
    }

    #[test]
    fn a_coil_write_reads_back_once_the_plant_advances() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Rcs1, &plant);
        let echo = exchange(
            &mut h,
            &Request::WriteSingleCoil {
                address: 1,
                value: false,
            },
        )?;
        assert_eq!(
            echo,
            Response::WriteSingleCoil {
                address: 1,
                value: false
            }
        );
        plant.lock().advance(1_000);
        let coils = exchange(
            &mut h,
            &Request::ReadCoils {
                address: 0,
                quantity: 4,
            },
        )?;
        assert_eq!(bits_of(coils, 4), vec![true, false, true, true]);
        Ok(())
    }

    #[test]
    fn a_rejected_multiple_coil_write_changes_nothing() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Rcs1, &plant);
        // Pump B would stop, but the heater write that follows is refused while
        // the pressurizer controller is automatic.
        let response = exchange(
            &mut h,
            &Request::WriteMultipleCoils {
                address: 1,
                values: vec![false, false],
            },
        )?;
        assert_eq!(
            exception_code(&response),
            Some(Exception::IllegalDataValue.code())
        );
        assert_eq!(plant.lock().snapshot().operator_actions, 0);
        plant.lock().advance(1_000);
        let coils = exchange(
            &mut h,
            &Request::ReadCoils {
                address: 0,
                quantity: 4,
            },
        )?;
        assert_eq!(bits_of(coils, 4), vec![true; 4], "pump B still runs");
        Ok(())
    }

    #[test]
    fn a_multiple_register_write_sets_the_valves_in_manual() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Bop1, &plant);
        // Feed level A goes to manual, so its valve accepts a demand.
        let mode = exchange(
            &mut h,
            &Request::WriteSingleCoil {
                address: 4,
                value: false,
            },
        )?;
        assert_eq!(
            mode,
            Response::WriteSingleCoil {
                address: 4,
                value: false
            }
        );
        let echo = exchange(
            &mut h,
            &Request::WriteMultipleRegisters {
                address: 0,
                values: vec![300],
            },
        )?;
        assert_eq!(
            echo,
            Response::WriteMultiple {
                address: 0,
                quantity: 1
            }
        );
        assert_eq!(plant.lock().snapshot().operator_actions, 2);

        // Feed level B is still automatic, so the write to valve B is refused
        // and valve A's demand in the same write does not apply.
        let response = exchange(
            &mut h,
            &Request::WriteMultipleRegisters {
                address: 0,
                values: vec![400, 400],
            },
        )?;
        assert_eq!(
            exception_code(&response),
            Some(Exception::IllegalDataValue.code())
        );
        assert_eq!(plant.lock().snapshot().operator_actions, 2);
        Ok(())
    }

    #[test]
    fn writes_outside_the_block_are_illegal_data_addresses() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Rps1, &plant);
        let register = exchange(
            &mut h,
            &Request::WriteSingleRegister {
                address: 1,
                value: 0,
            },
        )?;
        assert_eq!(
            exception_code(&register),
            Some(Exception::IllegalDataAddress.code())
        );
        // Coil 3 is past the three coils of the reactor protection block.
        let coil = exchange(
            &mut h,
            &Request::WriteSingleCoil {
                address: 3,
                value: true,
            },
        )?;
        assert_eq!(
            exception_code(&coil),
            Some(Exception::IllegalDataAddress.code())
        );
        Ok(())
    }

    #[test]
    fn an_unimplemented_function_is_an_illegal_function() -> Result<(), Box<dyn Error>> {
        let plant = plant();
        let mut h = harness(Plc::Bop1, &plant);
        // Function 8, diagnostics, is not served.
        let response = exchange(
            &mut h,
            &Request::Other {
                function: 8,
                data: vec![0, 0, 0, 0],
            },
        )?;
        assert_eq!(
            exception_code(&response),
            Some(Exception::IllegalFunction.code())
        );
        Ok(())
    }

    #[test]
    fn plant_rejections_map_to_the_modbus_table() {
        for reason in [Rejection::OutOfRange, Rejection::WrongMode] {
            assert_eq!(
                exception_for(reason).code(),
                Exception::IllegalDataValue.code(),
                "{reason:?}"
            );
        }
        for reason in [
            Rejection::Faulted,
            Rejection::Tripped,
            Rejection::AlreadyActive,
            Rejection::NotActive,
            Rejection::TripConditionPresent,
            Rejection::StaleRevision,
        ] {
            assert_eq!(
                exception_for(reason).code(),
                Exception::ServerDeviceFailure.code(),
                "{reason:?}"
            );
        }
    }
}
