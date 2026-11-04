# MPTCP verification

This follows the DNS verification workflow: TLC checks bounded state machines,
Lean checks pure-function theorems and writes reference vectors, and Rust runs
on every vector. The model boundaries and the reason for each abstraction are
in [tla/README.md](tla/README.md) and [lean/README.md](lean/README.md).

```sh
export TLA2TOOLS=/home/souvik/.cache/adorably-fv/tla2tools.jar
export JAVA=/home/souvik/.local/jdk21/bin/java
export TMPDIR="$CARGO_TARGET_DIR/mptcp-verify/temp"
mkdir -p "$TMPDIR"
systemd-run --user --scope -p MemoryMax=12G -q cargo xtask mptcp-verify all
```

The runner accepts `tlc [spec] [config]`, `lean`, `vectors [seed]`, `diff [seed]`,
and `all`. With no seed it uses every seed from 1 through 8. A seed changes the
keys and byte payloads; it does not change the exhaustive length/flag cases.

Each cargo, Lake, generator and TLC subprocess has its own 12 GiB systemd scope.
They run sequentially. TLC uses `-Xmx6g`, two workers for passing configurations
and one for counterexamples. Each passing configuration runs once with its
entire original configuration and every invariant and action property enabled.
The report marks its properties passed only after complete error-free exploration
and a successful process exit; any failure fails the grouped configuration.
This avoids exploring an identical graph again for each property. Ablation
properties still run separately and must violate exactly the property named in
their configuration; a parse error, a crash, and a passing ablation fail the run.
The Lean axiom audit rejects anything beyond `propext`, `Quot.sound`, and
`Classical.choice`.

Logs, vectors, TLC working files, and `SUMMARY.txt` go under
`$CARGO_TARGET_DIR/mptcp-verify/` (or `target/mptcp-verify/`). Logs are written
while children run. Compilation and generation are separate commands, with
separate logs. The generator streams one JSON case at a time and never retains
an entire suite. No generated vectors or Lake output belong in git.

The differential test is explicitly named, as in DNS verification:

```sh
systemd-run --user --scope -p MemoryMax=12G -q \
  env MPTCP_VECTORS="$CARGO_TARGET_DIR/mptcp-verify/vectors/1" \
  cargo test -p fictionet --test mptcp_vectors -- --nocapture
```

| Suite | Compared with Rust |
|---|---|
| Codec | Exact error variant and parameters, every decoded semantic field, and canonical encoded bytes; all 256 first bytes, every DSS flag combination, valid and invalid lengths through overlong options, and MP_CAPABLE algorithm/version cases |
| IPv4 codec | Every typed field and canonical byte, all kinds and lengths, route pointers, all timestamp overflow/flag combinations, malformed framing and EOL termination |
| IPv4 echo | Linux reply fields, destination and bytes for RR, Timestamp, source route reversal, overflow, prespecified address classification, duplicates, option ordering and malformed input |
| Crypto | SHA-256 token and IDSN, full MP_JOIN HMAC with ordered keys/nonces, DSS checksum with odd/even payloads and DATA_FIN length |
| Sequence | Short and full sequence expansion, both wrapping boundaries and the signed half-window tie |
| Layout | Real simulated TCP SYN-ACK option order, NOPs, padded header length and MPTCP space, using default core settings or `fictionet_extras::linux::settings()` |
| Transmit | Every full-sized mapping through a 32-bit subflow wrap, then retransmissions on both sides of the wrap |
| Data | Output bytes, data ACK, error and fallback after each step of reordered mappings, reinjection, DATA_FIN, checksum failure and fallback traces |

These tests use pure protocol code and simulated IP endpoints. They do not open
a NIC, run driver binaries, attach XDP, or change host networking.

## Bugs exposed by differential traces

The receive reference exposed bytes delivered after DATA_FIN, an accepted FIN
that moved or preceded already accepted data, and a fatal mapping error whose
state could subsequently change to plain TCP fallback. The receive path now
keeps an immutable FIN boundary, checks both queued and delivered data, rejects
fallback after FIN, and stops processing once an error occurs. Rust regressions
are `data_fin_rejects_later_data_and_fallback`,
`data_fin_cannot_move_or_precede_accepted_data`, and `mapping_errors_are_terminal`.

The transmit reference exposed a full data sequence jumping backward by 2^32
after the subflow sequence wrapped. The sender now expands short offsets near
its full send position and advances that position only for new data. The Rust
regression `outgoing_data_sequence_survives_subflow_wrap_and_retransmission`
crosses the wrap and checks retransmissions on both sides. These fixes live in
`src/stdlib/protocols/mptcp.rs`; the honeypot's segment callback borrows that
state mutably when sending.
