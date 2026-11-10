# IP, UDP and ICMP: Lean 4 verification

Machine-checked proofs about the IP layer's pure functions, and an
executable Lean reference that writes test vectors for the differential
test `tests/ip_vectors.rs`. Lean core only, no Mathlib; the toolchain is in
`lean-toolchain`.

```sh
cd verification/packet-udp/lean
lake build                  # every proof, Ip/Axioms.lean and the generator
lake exe gen <dir> <seed>   # writes <dir>/<kind>.json
IP_VECTORS=<dir> cargo test --test ip_vectors -- --nocapture
```

## Checksum, header and UDP

(to be written)

## Reassembly

(to be written)

## IPv6 extension headers and ICMP

(to be written)
