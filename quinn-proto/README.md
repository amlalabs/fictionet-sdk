# Fictionet Quinn protocol engine

Vendored from the published quinn-proto 0.11.19 crate in the local registry
cache, retaining its licenses. The package is renamed to
fictionet-quinn-proto and is not published. Cargo registry metadata and
the upstream lockfile are omitted; the workspace lockfile is authoritative.

This is the deterministic transport engine, without Quinn’s asynchronous
socket runtime. Vendoring alone makes no claim of formal verification or
Fictionet resource accounting. Local changes and their evidence belong in
verification/quic/README.md as they are implemented.

The crypto adapter uses the workspace’s vendored fictionet-rustls with
ring. The upstream AWS LC and platform verifier conveniences are removed:
the former is not provided by this rustls fork, and the latter accepts the
registry rustls type. Callers can supply an explicit verifier or root store.
No rustls source changes are required for this integration.

Connection ID generators and their factories receive the endpoint RNG,
including the initial destination ID provider. Custom generators must use
that source for reproducible routing. Configuration constructors that make
reset or token keys, TLS cryptography and calendar time still require
explicit world sources; seeding the endpoint alone does not make the whole
handshake deterministic.
