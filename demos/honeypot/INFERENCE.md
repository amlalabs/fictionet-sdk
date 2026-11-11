Offline inference reads bare trap observations or the evidence writer's JSONL
envelopes. Keep each input file scoped to one agent trace and one trap family;
unrelated packet records are ignored. Inputs mixing source IPs, run identifiers or destination services are rejected. Model and harness declarations remain
claims, not authenticated identities.

The command lives in xtask and opens no network sockets:

```text
cargo run -p xtask --features shibboleth -- shibboleth-infer split evidence.jsonl traces
cargo run -p xtask --features shibboleth -- shibboleth-infer fit enrollment.json MODEL=trace.jsonl OTHER=other.jsonl
cargo run -p xtask --features shibboleth -- shibboleth-infer enroll enrollment.json expanded.json NEW=new-trace.jsonl
cargo run -p xtask --features shibboleth -- shibboleth-infer classify expanded.json trace.jsonl
cargo run -p xtask --features shibboleth -- shibboleth-infer classify - trace.jsonl
cargo run -p xtask --features shibboleth -- shibboleth-infer fingerprint expanded.json trace.jsonl
```

Split extracts typed trap records into separate files by run, source IP and
destination address and port, and prints each file's grouping key. It refuses
to overwrite existing output files. Source ports and sessions remain in the
records, but this grouping cannot distinguish different agents sharing one
source IP. Missing provenance is grouped conservatively as unknown.

Fit once on labeled training traces. Enrollment keeps that vocabulary and its
smoothed inverse document frequencies fixed. Each prose input is represented
by lowercase, word-boundary character n-grams of lengths two through five;
normalized TF-IDF vectors are averaged within each trace, then across a model's
traces. Classification centers on the mean of all enrolled trace fingerprints
and compares cosine similarities. Separate enrollment and evaluation traces.

The first structurally valid, non-blacklisted declaration takes precedence even
when a negotiation retry rejected that request. Without a declaration, the
nearest enrolled template is returned unless there is a tie, no usable prose,
or fewer than two enrolled models. This does not identify unseen models or
provide a calibrated confidence. Scores and declarations are reported separately.

Credential and overlapping-check readings intersect compatible harnesses from
the measured panel. The result remains an open set: unknown harnesses, manual
filters, scheduling and explicit timeouts can produce the same evidence. A caller closing the silent hold at 120 seconds (within two seconds) is compatible with OpenCode; an answered hold with another request arriving at that boundary is compatible with Claude Code. Four distinct checks without overlap are compatible with Hermes Agent or Claude Code. Other timing remains unconstrained. These are measured defaults from the paper, not immutable runtime properties.
