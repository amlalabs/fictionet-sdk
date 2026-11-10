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
  buffer its record arrived in instead of copying it out.
  `CommonState::take_sendable_tls_chunk` transfers the sole whole queued
  ciphertext buffer when its capacity fits a caller's limit. Multiple
  chunks, partially consumed chunks and oversized allocations stay queued
  for the existing bounded, coalescing `write_tls` path. Both hand over the
  bytes with the charge that pays for them (`budget::PaidBytes`).
- A connection's buffers can be paid from a budget the caller passes in
  (`budget::BufferBudget`, through `Acceptor::with_budget` or
  `ServerConnection::with_budget`); there is no global or thread-local
  state. The records read and not yet processed, the plaintext decrypted
  and not yet taken, the plaintext written during the handshake, and the
  records queued to send are each charged before they grow, and their
  capacities are exact, so what is charged is what they hold. A growth the
  budget refuses changes nothing: `read_tls` fails with `OutOfMemory`
  having read nothing; `process_new_packets` stops before the record or
  message it cannot pay for and `CommonState::wants_budget` says so;
  writes take fewer bytes; `Accepted::into_connection` gives the
  `Accepted` back (`IntoConnectionError::Unpaid`); `send_close_notify`
  returns `false` and `refresh_traffic_keys` fails with
  `Error::BudgetExhausted`. Output rustls makes for a received message is
  paid from room charged before the message is taken: a record for a
  handshake message, plus the certificate chain once it is chosen, and
  three small records after the handshake. Output that outgrows its room
  and is refused by the budget is dropped and fails the connection with
  `Error::BudgetExhausted`. Without a budget nothing is charged and every
  growth fits, as upstream.
- A connection holds no buffer it does not need. `read_tls` reads no
  further than the end of the record arriving, into a buffer of exactly
  that record's size (its header first, then the rest), and reads nothing
  more while a whole record waits for `process_new_packets`, failing with
  `ErrorKind::Other`. Upstream reads 4 KiB at a time into a buffer it
  keeps. Application data is decrypted in place, and once the record has
  been authenticated its plaintext stays in that buffer, moved to the
  front, which joins the plaintext queue with its charge; the next record
  starts a buffer of its own. There is no separate copy of the plaintext.
  A buffer is freed, not just emptied, once nothing is in it: the receive
  buffer once its records are processed, each queue (and its places) once
  drained, and the handshake joiner's spans once a flight is handed out.
  An idle connection holds no buffer at all. Records that fail trial
  decryption leave the buffer at once.

The fork retains upstream `no_std` support and builds for
`wasm32-unknown-unknown`. Fictionet configures ring's browser randomness
backend for that target; its simulated TLS provider supplies explicit
world entropy. TLS protocol behavior is otherwise unchanged.
