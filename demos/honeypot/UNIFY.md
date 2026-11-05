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
