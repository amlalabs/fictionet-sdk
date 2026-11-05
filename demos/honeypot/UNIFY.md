# Honeypot reuse

The honeypot already uses the SDK's IP, TCP, MPTCP, Ethernet, ARP, neighbor
discovery, HTTP and SSH codecs. Reuse should remove a second implementation
of a rule, without making different network roles pretend to be the same.

## Frame queues and losses

The raw NIC pump and its in-memory wire now use the same attachment
constructor. Receive and transmit queues use the same `QueueStats` enqueue
operation. A full queue discards and counts; closure remains an error, and
an invalid frame never enters the queue. Async sends still wait for space.
The driver still publishes failures before closing its channels and still
owns completion of flush requests.

The raw frame log includes `tx_queue_dropped` beside `rx_queue_dropped`.
Both are deltas since the last accepted record. An outgoing frame is logged
after its enqueue attempt, so that very record includes its rejection.
Failed log writes retain the unreported counts. Device/backend loss stays
unknown (`nic_rx_dropped: null`). The README now describes the actual
receive behavior: keep reading and count discarded frames.

## Separate roles

`ethernet::Link` is the gateway of one VM. Its ARP reply policy is proxy
ARP for addresses other than a probe/announcement, subject to its configured
family and guest checks. Putting it on a shared cloud segment would claim
addresses it does not own, including a real gateway's. `ethernet::Host`
answers only for its own addresses and performs neighbor reachability,
IPv6 duplicate-address detection and multicast membership. They already
share frame construction and the ARP/NDP/MLD codecs. Keep both state machines.

Keep the transport execution models separate too. VFIO polls device
completion and owns DMA memory; vhost-user consumes guest descriptors from
callbacks and wakes through eventfd; the CLI multiplexes nonblocking file
descriptors and relay messages. A single polling pump would add adapters
and change readiness, flush and shutdown semantics. Their bounded queues
are real device/transport contracts, not a reason to merge those loops.

## Linux behavior and protocol evidence

The reusable MPTCP listener now lives at `fictionet_extras::linux::mptcp`.
Its timestamp input is a callback in milliseconds since midnight UTC;
it no longer depends on the demo's wall-clock type. Plain TCP and MPTCP
share the IPv4 SYN-reply address classification and retransmission policy
inside `linux`. JOIN cookies still retain the IPv4 options selected for
the SYN-ACK. Simply wrapping the listener and deleting its internal hook
would have lost those retained options, so that approach was rejected.

Generic MPTCP codecs and `DataLevel` stay in core. Linux option acceptance,
last-option preference, JOIN limits, cookie slots and reset reasons stay
in extras. This listener still delivers application data through its
primary connection and drains joined subflows; moving it does not turn it
into a complete multipath application endpoint.

TCP option walking now delegates to the same smoltcp parser in the endpoint,
dissector and differential probe. Core's lossless iterator retains each
option's original bytes, end-of-list padding and a malformed suffix. The
probe keeps its raw evidence and presentation. The dissector no longer
inventories malformed-size SACK options as valid blocks. The observer
already used the shared TCP/MPTCP codecs; its JSON enums remain application
presentation, not another protocol implementation. Hex serialization uses
the existing dissector helper.

The differential HTTP probe uses core's whole-response decoder instead of
its own Content-Length parser and header/body caps. It records the decoder's
original wire bytes, including header order and body framing. Unconsumed
read-ahead stays in its BufReader for the next response or idle observation.
