//! Diameter messages and AVPs, as a world playing an HSS or a charging
//! server reads them.
#![no_main]

use fictionet::stdlib::diameter::{Avp, MAX_AVP_DATA, Message, harness};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check_bytes(data);
    let mut built = Message::request(u32::from(data.first().copied().unwrap_or(0)) << 20, 0, 1, 2);
    built.error = true;
    built.avps.push(Avp {
        code: 1,
        vendor: Some(0),
        mandatory: true,
        protected: false,
        data: data.to_vec(),
    });
    contract::check_wire_value(&built);
    if data.first() == Some(&0xff) {
        // Keep the command valid so the oversized AVP reaches the length check.
        built.command = 1;
        built.avps[0].data = vec![0; MAX_AVP_DATA + 1];
        contract::check_wire_value(&built);
    }
});
