//! Git packets and payloads through shared contracts.
#![no_main]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Stream, Wire, contract, test_support::decode_all};
use fictionet::stdlib::git_protocol::{
    Advertisement, Band, Bands, CapabilityAdvertisement, ClientLine, LsRef, LsRefsArg, MAX_DATA,
    MAX_PACKET, Packet, ProtoRequest, ServerLine, ServiceHeader, Sideband, V2Request, band_packets,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Packet>::new, data, 2 * MAX_PACKET);
    contract::check_decode_with_alloc_limit(|| Bands, data, 2 * MAX_PACKET);
    contract::check_wire::<Packet>(data);
    contract::check_wire::<ProtoRequest>(data);
    contract::check_wire::<ServiceHeader>(data);
    contract::check_wire::<Advertisement>(data);
    contract::check_wire::<CapabilityAdvertisement>(data);
    contract::check_wire::<V2Request>(data);
    contract::check_wire_value(&Packet::Data(data[..data.len().min(MAX_DATA + 1)].to_vec()));
    // Bytes still buffered are handed over without changes, even after a bad packet.
    let mut stream = Stream::new(Frames::<Packet>::new());
    let pushed = stream.push(data);
    let mut used = 0;
    while let Some(Ok(packet)) = stream.next() {
        used += packet.to_bytes().unwrap().len();
    }
    let (buffer, _) = stream.into_parts();
    assert_eq!(buffer.unread(), &data[used..pushed]);
    for packet in decode_all(Frames::<Packet>::new, data).0 {
        if let Some(bytes) = packet.data() {
            contract::check_wire::<ClientLine>(bytes);
            contract::check_wire::<ServerLine>(bytes);
            contract::check_wire::<LsRef>(bytes);
            contract::check_wire::<LsRefsArg>(bytes);
            if let Ok(request) = ProtoRequest::from_data(bytes) {
                assert!(request.to_bytes().is_ok(), "{request:?}");
                contract::check_wire_value(&request);
            }
        }
    }
    if let Ok(V2Request::Command(command)) = V2Request::parse(data) {
        if let Ok(args) = command.fetch_args() {
            for arg in args {
                assert!(arg.to_bytes().is_ok(), "{arg:?}");
                contract::check_wire_value(&arg);
            }
        }
        if let Ok(args) = command.ls_refs_args() {
            for arg in args {
                assert!(arg.to_bytes().is_ok(), "{arg:?}");
                contract::check_wire_value(&arg);
            }
        }
    }
    let max = data.first().map_or(0, |b| usize::from(*b) * 300);
    let mut bytes = Vec::new();
    for packet in band_packets(Sideband::Pack, data, max) { packet.write(&mut bytes).unwrap(); }
    let mut back = Vec::new();
    for item in decode_all(|| Bands, &bytes).0 {
        let Band::Data(Sideband::Pack, payload) = item else { panic!("unexpected band") };
        back.extend(payload);
    }
    assert_eq!(back, data);
});
