/-
  The axioms each headline theorem depends on.

  Expected: every `#print axioms` line lists only `propext`, `Quot.sound` and `Classical.choice`,
  Lean's standard axioms, or a subset of them. `sorryAx` would mean an unfinished proof.
  `cargo xtask tls-verify lean` checks this.
-/
import TlsRecord.Header
import TlsRecord.Nonce

open TlsRecord

#print axioms accept_within_limit
#print axioms accept_unprotected
#print axioms accept_tls13
#print axioms accept_known
#print axioms accept_nonempty
#print axioms overflow_iff
#print axioms accept_shorter
#print axioms limits
#print axioms limits_ordered
#print axioms Nonce.nonce_unique
#print axioms Nonce.wire_chain
#print axioms Nonce.wire_suffix
#print axioms Nonce.live_loses_nothing
#print axioms Nonce.refused_changes_nothing
#print axioms Nonce.old.hole_after_drop
#print axioms Nonce.old.record_without_key_update
