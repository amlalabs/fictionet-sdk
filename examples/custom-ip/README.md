# Replacing the IP layer

`HopLimit` copies the IP layer's state machine and owns its validation,
fragment reassembly, packet queues and deadlines. It uses public parsing and
reassembly helpers and constructs `CheckedIpPacket` values. It contains no
stdlib `IpLayer`.

The world installs it through `packet::Factory` under unchanged TCP, UDP and
HTTP applications. It applies the selected hop limit to transport packets and
its own ICMP replies. `Layer::take_command` receives `Env`, so the rewrite uses
`Chunk::make_mut` with the correct budget. Unique backing keeps its charge;
shared backing is copied only after reserving the copy. A refused reservation
leaves the packet queued until its backing can be edited.

Fragment reassembly is bounded engine storage, as in the stdlib IP layer.
Payload charges follow outgoing packets until their final owner releases them.

Run `cargo test -p fictionet-custom-ip`. The world test checks unchanged HTTP
behavior and valid IPv4 checksums with the chosen hop limit. The budget tests
cover IPv4 and IPv6 output ownership, and a shared packet blocked until the
other owner releases it.
