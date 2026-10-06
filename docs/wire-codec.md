# Datagram and token codec APIs

The BACnet, DTLS, IKE, L2TP, NetBIOS datagram and name services, NTLMSSP,
NTP, PCP, TFTP, VXLAN and WireGuard modules use `stdlib::codec::Wire`.
Import the trait to parse a complete unit or append its bytes. A write
error leaves the destination unchanged. `Wire::to_bytes` is the fallible
convenience method built on `write`.

There are no compatibility writers or decoder wrappers. Packet boundaries
come from the caller. The TFTP netascii text converter uses
`Stream<Netascii>` and retains at most two input bytes. It does not frame
TFTP packets.

```rust
use fictionet::stdlib::{codec::Wire, vxlan::Packet};

let packet = Packet { vni: 7, frame: vec![1, 2, 3] };
let mut datagram = Vec::new();
packet.write(&mut datagram).unwrap();
assert_eq!(Packet::parse(&datagram), Ok(packet));
```

Use named units for collections and context:

| Module | Units and composition |
|---|---|
| BACnet | `Tag`, `Value`, `Values`, `ContextValue<TYPE>`, `Bvlc`, `Npdu`, `Apdu`, `WhoIs`, `IAm`. Service constructors return `Result<Apdu, Error>`. |
| DTLS | `Record<CID_LEN>`, `Datagram<CID_LEN>`, `Fragment`, `Fragments`, `Handshake`, and the three hello bodies. Fragment constructors return results. |
| IKE | `Header`, `Message`, `NatT`, and `Payloads<FIRST>`. `NatT::Ike(message)` constructs a UDP encapsulation. |
| L2TP | `Avp`, `ControlMessage`, `V2Packet`, `V3Control`, `V3Data<COOKIE_LEN>`, `Packet`. Control packet constructors return results. |
| NBDGM | `Name` and `Packet`. `Packet::split` returns a result and retains all data. |
| NBNS | `Name`, `RrName`, `Packet`. Writers preserve all records and the TC flag. Callers choose a reply that fits their datagram budget. |
| NTLMSSP | Tokens, `Version`, `AvPair`, `AvPairs`, `UnicodeName`, LM and NT responses, `ClientChallenge`, and `MicInput`. `Authenticate::mic_input` preserves the original token layout while zeroing its MIC. |
| NTP | `Packet`, `Timestamp`, `KissCode`. |
| PCP | PCP and NAT-PMP requests and responses, plus `Reply`. `receive` and `error_reply` return values to serialize. |
| TFTP | `Packet` and `NetasciiByte`. `Netascii` reads text with the shared driver, including CR pairs split between DATA blocks. |
| VXLAN | `Packet` and `GpePacket`. |
| WireGuard | The four message types, `Message`, and `Plaintext`. `Plaintext::padded` constructs a value for encryption. `Initiation::MAC1_INPUT`, `MAC2_INPUT`, and the corresponding `Response` constants select ranges in serialized bytes. |

Protocol negotiation still selects or limits values when constructing a
reply. That is separate from serialization. For example, TFTP's transfer
constructor retains its explicitly named option-clipping helper.

All targets check the shared wire contract. TFTP also checks the shared
decoder contract and its allocation bound. Fragment reassembly and replay
windows remain protocol state machines.

## New refusals

Exact unit readers refuse bytes beyond the unit boundary. This includes
BACnet tags and single values, DTLS single records and fragments, IKE
headers, L2TP AVPs and length-bearing packets, NBDGM names, NBNS packets,
NTLMSSP tokens and AV lists, and fixed NAT-PMP messages. Use the named
collection unit when the payload contains several units. NTLMSSP tokens
may still contain field gaps and overlaps; only bytes beyond the last
in-bounds field are newly refused. NTLMv2 client-blob trailing bytes remain
stored data. NBNS also refuses compressed input whose expanded value cannot
be serialized within `MAX_PACKET`. `UnicodeName` refuses input above
`MAX_FIELD`. IKE's NAT-T reader refuses ESP datagrams above `MAX_MESSAGE + 4`.
MIC-input readers require an AUTHENTICATE token with a zero MIC.

The writers now refuse these values instead of changing them:

| Module | Values refused |
|---|---|
| BACnet | Tag number 255; application opening or closing tags; oversized strings, bit strings, tables, messages, bodies or network addresses; out-of-range object identifiers and Who-Is limits; non-device I-Am identifiers; empty or invalid source addresses and invalid destination networks; inconsistent vendor fields; APDU fields wider than their wire fields. |
| DTLS | Oversized record payloads, handshake bodies, sessions, cookies, suites, compression lists or extension blocks; sequence numbers wider than 48 bits; unified epoch bits above three; mismatched connection IDs; invalid fragment ranges; empty suite or compression lists; duplicate extension types; excess record or fragment counts; records after a unified record without a length. |
| IKE | Oversized messages, payloads, nested lists, SPIs, attributes or selector data; fields outside their bit widths; invalid encrypted-fragment counts or next-payload fields; payloads after SK or SKF; typed payloads or selectors stored as an incompatible `Other`; inconsistent Delete SPI lengths. |
| L2TP | Oversized AVPs, AVP lists, control bodies, payloads or offset padding; reserved AVP bits wider than four bits; nonempty ZLB values; invalid control flags or missing control sequence numbers; control bodies the control-message reader refuses; cookie lengths that disagree with the selected unit; message-type variants that would change. Stored reserved AVP bits are preserved. |
| NBDGM | Empty or oversized scope labels, oversized names or packet data, and code variants that would change. Splitting refuses data above `MAX_REASSEMBLED` instead of discarding its end. |
| NBNS | Empty or oversized labels; oversized names, record data, owner lists, node-status lists, sections or packets; result codes wider than four bits; opcode and record-name variants that would change; opaque NS data; opaque NB or NBSTAT data that would read as a typed variant. No records are dropped and TC is not changed. |
| NTLMSSP | The existing writer refusals remain. New named units also refuse oversized Unicode fields, nonempty AV end markers and invalid client blobs. |
| NTP | Versions outside 1 through 7; oversized trailers; trailers not divisible by four; `KissCode::Other` values that name a defined code. |
| PCP | Oversized messages, opaque bodies or options; unaligned opaque PCP bodies; duplicate request singleton options; opaque known request options; opcodes, result codes or option variants that would change on reading. |
| TFTP | NULs or oversized strings; requests above 512 bytes; oversized DATA or option lists; repeated option names; options that would need to be shortened or omitted. |
| VXLAN | No additional value refusals. Existing VNI, payload and next-protocol checks now use `Unwritable`. |
| WireGuard | No additional message-value refusals. Existing ciphertext and plaintext-size checks now use `Unwritable`. MAC input selection uses ranges rather than separate byte writers. |

Writers also report `Unwritable` when reserving destination space fails.
