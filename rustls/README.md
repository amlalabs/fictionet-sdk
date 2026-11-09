# Fictionet's rustls fork

This fork of rustls 0.23.46 supplies TLS 1.2 and TLS 1.3 to Fictionet's
simulated connections. It retains the upstream Apache-2.0, ISC, and MIT
licenses. The package is named `fictionet-rustls`; its library remains
`rustls`. Core uses this path dependency. Real host transports continue to
use upstream rustls through their transport libraries.

The divergences from upstream are:

- `CryptoProvider` owns `secure_random`, `key_provider`, and each entry in
  `kx_groups` through `Arc` trait objects. Key exchange state and the
  negotiated-group accessor retain shared ownership, allowing providers to
  carry a world's entropy without static storage. ECH state also retains
  its random provider through `Arc`.
- Once `close_notify` or a fatal alert is sent, nothing more is queued:
  `send_fatal_alert` and the `no_renegotiation` warning do nothing then.
  Upstream queues the alert after `close_notify` and, in debug builds,
  fails a `debug_assert` when a peer sends a bad record after it.
- Ring group constants expose their copyable `KxGroup` implementation so
  callers can construct owned groups. The default provider allocates its
  three groups and random/key provider objects with `Arc`.
- The AWS LC backend, its FIPS provider constructor, and the `aws-lc-rs`,
  `aws_lc_rs`, `fips`, and `prefer-post-quantum` features are removed.
  Ring replaces AWS LC in the default feature set. Provider-independent
  FIPS capability reporting remains available to custom implementations.
- The `brotli` and `zlib` features and bundled compression implementations
  are removed. Default compressor and decompressor lists are empty;
  custom certificate compression remains supported.
- Upstream has no `ech` feature. Its provider-independent ECH API and wire
  processing are retained, including handling unsolicited extensions.
  No built-in HPKE/ECH backend remains after removing AWS LC; using client
  ECH requires a custom HPKE implementation.
- Documentation and examples use ring and the owned provider interfaces.
  AWS LC-only tests and compression-backend tests were removed with those
  implementations. Other upstream unit tests remain.
- Unit-test and benchmark fixtures omitted from the crates.io package are
  copied unchanged from the upstream `v/0.23.46` source archive. Certificate
  fixtures live under `test-ca/`, and source references point there.
  The upstream message fuzz corpus is preserved unchanged under
  `fuzz/corpus/message/`; its unit test resolves that path from the crate
  manifest directory.
  The standalone benchmark uses those fixtures directly instead of the
  upstream workspace-only `rustls-test` helper.
- The upstream certificate-generation example, registry metadata, nested
  lockfile, original workspace manifest, external-type audit metadata, and
  unused development dependencies are omitted. The crate belongs to the
  Fictionet workspace and uses its lockfile.
- Accessors let Fictionet's TLS layer move bytes without extra copies:
  `CommonState::sendable_tls_len` says how many bytes `write_tls` has
  queued, so the layer allocates exactly that, and
  `Reader::take_first_chunk` hands over the decrypted plaintext in the
  buffer that holds it instead of copying it out.
  `CommonState::take_sendable_tls_chunk` transfers the sole whole queued
  ciphertext buffer when its capacity fits a caller's reservation. Multiple
  chunks, partially consumed chunks and oversized allocations stay queued
  for the existing bounded, coalescing `write_tls` path.

The fork retains upstream `no_std` support and builds for
`wasm32-unknown-unknown`. Fictionet configures ring's browser randomness
backend for that target; its simulated TLS provider supplies explicit
world entropy. TLS protocol behavior is otherwise unchanged.
