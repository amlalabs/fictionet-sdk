//! Kani harnesses over `layer::Framed`.
//!
//! Included from `src/stdlib/layer/framed.rs` under `cfg(kani)` as a child
//! module, so every harness drives the real `Framed`, `Stream`, `Buffer`,
//! `Budget`, `Charge`, `Chunk` and `Driver`, and may read `Framed`'s
//! private fields. The other files here are included from the code they
//! check: `plc.rs` from `demos/nuclear/world/src/plc.rs`, `ntp.rs` from
//! `demos/search/world/src/ntp.rs`, `ntp_reply.rs` from
//! `src/stdlib/protocols/ntp.rs`, `admission.rs` from
//! `src/stdlib/services/stack/mod.rs`. `verification/layer-runtime/VERIFICATION.md`
//! says what each harness proves and the bound it proves it to.

mod framed;
