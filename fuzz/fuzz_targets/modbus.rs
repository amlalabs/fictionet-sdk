//! Modbus/TCP frames, requests and responses, as a world playing a PLC
//! reads them, and values a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Wire, test_support::decode_all};
use fictionet::stdlib::modbus::{Exception, Frame, Frames, MAX_PDU, Request, Response, function};
use libfuzzer_sys::fuzz_target;

/// A PDU read as a request and as a response. Whatever reads is written
/// back, and reads back the same.
fn pdu(pdu: &[u8]) {
    if let Ok(req) = Request::parse(pdu) {
        let bytes = req.to_pdu().unwrap();
        assert!(bytes.len() <= MAX_PDU);
        assert_eq!(Request::parse(&bytes), Ok(req));
    }
    if let Ok((function, resp)) = Response::parse(pdu) {
        let bytes = resp.to_pdu(function).unwrap();
        assert!(bytes.len() <= MAX_PDU);
        assert_eq!(Response::parse(&bytes), Ok((function, resp)));
    }
}

/// A request built from fuzz bytes, valid or not.
fn request(u: &mut Unstructured) -> Result<Request> {
    let address = u.arbitrary()?;
    let n = u.int_in_range(0..=2100usize)?;
    Ok(match u.int_in_range(0..=8u8)? {
        0 => Request::ReadCoils { address, quantity: n as u16 },
        1 => Request::ReadDiscreteInputs { address, quantity: n as u16 },
        2 => Request::ReadHoldingRegisters { address, quantity: n as u16 },
        3 => Request::ReadInputRegisters { address, quantity: n as u16 },
        4 => Request::WriteSingleCoil { address, value: u.arbitrary()? },
        5 => Request::WriteSingleRegister { address, value: u.arbitrary()? },
        6 => Request::WriteMultipleCoils {
            address,
            values: (0..n).map(|_| u.arbitrary()).collect::<Result<_>>()?,
        },
        7 => Request::WriteMultipleRegisters {
            address,
            values: (0..n).map(|_| u.arbitrary()).collect::<Result<_>>()?,
        },
        _ => Request::Other {
            function: u.arbitrary()?,
            data: (0..n).map(|_| u.arbitrary()).collect::<Result<_>>()?,
        },
    })
}

/// A response built from fuzz bytes, valid or not.
fn response(u: &mut Unstructured) -> Result<Response> {
    let address = u.arbitrary()?;
    let n = u.int_in_range(0..=2100usize)?;
    Ok(match u.int_in_range(0..=6u8)? {
        0 => Response::Bits((0..n).map(|_| u.arbitrary()).collect::<Result<_>>()?),
        1 => Response::Registers((0..n).map(|_| u.arbitrary()).collect::<Result<_>>()?),
        2 => Response::WriteSingleCoil { address, value: u.arbitrary()? },
        3 => Response::WriteSingleRegister { address, value: u.arbitrary()? },
        4 => Response::WriteMultiple { address, quantity: n as u16 },
        5 => Response::Exception(Exception::Other(u.arbitrary()?)),
        _ => Response::Other((0..n).map(|_| u.arbitrary()).collect::<Result<_>>()?),
    })
}

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let req = request(&mut u)?;
    if let Ok(bytes) = req.to_pdu() {
        assert!(bytes.len() <= MAX_PDU);
        assert_eq!(Request::parse(&bytes), Ok(req));
    }
    let function: u8 = u.arbitrary()?;
    let resp = response(&mut u)?;
    if let Ok(bytes) = resp.to_pdu(function) {
        assert!(bytes.len() <= MAX_PDU);
        let (f, back) = Response::parse(&bytes).unwrap();
        assert_eq!(f, function & !function::EXCEPTION_FLAG);
        match (&resp, &back) {
            // Bits come back padded with zeros to a whole byte.
            (Response::Bits(a), Response::Bits(b)) => {
                assert_eq!(&b[..a.len()], &a[..]);
                assert!(b[a.len()..].iter().all(|&x| !x));
                assert_eq!(b.len(), a.len().div_ceil(8) * 8);
            }
            _ => assert_eq!(back, resp),
        }
    }
    let n = u.int_in_range(0..=300usize)?;
    let frame = Frame { transaction: u.arbitrary()?, unit: u.arbitrary()?, pdu: u.bytes(n)?.to_vec() };
    check_wire_value(&frame);
    if let Ok(bytes) = frame.to_bytes() {
        assert_eq!(<Frame as Wire>::parse(&bytes), Ok(frame));
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    check_decode(|| Frames, data);
    check_wire::<Frame>(data);

    let (frames, _) = decode_all(|| Frames, data);
    for frame in frames {
        check_wire_value(&frame);
        pdu(&frame.pdu);
    }
    // Any bytes as a PDU on their own, including ones longer than a frame
    // holds.
    pdu(data);
    let _ = built(data);
});
