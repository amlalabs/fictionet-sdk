# Bytes and what pays for them

Kani proofs over `fictionet-buf` (`buf/`): a `Chunk`'s cursor, its pieces
and its headroom, and how a `Pool` pays for its backings (`kani/mod.rs`,
compiled as a child of `buf/src/lib.rs`); and the checksum flags of the
core `Packet` (`kani/packet.rs`, a child of `src/packet.rs`, the only
module that can set a flag). Every harness calls the production code
through its API and stubs nothing. Backings are four bytes, as in the layer
proofs these came from: a symbolic allocation size took the solver past
the memory cap there.

| Harness | Claim |
| --- | --- |
| `a_chunk_cursor_keeps_the_rest_in_place` | for any four bytes, with or without a charge, two advances of any lengths that fit leave exactly the suffix; the charge stays whole and goes back on drop |
| `a_chunk_cursor_never_passes_the_end` | advancing past the end panics |
| `split_pieces_see_disjoint_bytes_of_one_backing` | a split at any point gives two pieces of one backing that see the two halves in order; editing either copies it out and leaves the other's bytes as they were |
| `a_shared_chunk_edit_preserves_ownership_and_budget` | a copied edit is charged before it is made, leaves its sibling unchanged, and both charges go back when the pieces do |
| `a_repay_pays_before_it_lets_go_and_a_refusal_changes_nothing` | `repay` charges the new budget before the old one lets go, whole or as a shared piece, and a refusal changes nothing |
| `prepend_needs_room_and_uniqueness` | `prepend` succeeds exactly when the headroom holds the bytes and no other piece shares the backing; the cursor moves back by that much, the old bytes follow unchanged, and nothing is charged |
| `a_pooled_backing_is_charged_to_one_budget_at_every_instant` | taken by either budget, admitted by either, shared or not, dropped in either order: after every step the budgets hold the pool's charge plus one slot while a piece lives, and a live chunk's charge is its capacity |
| `recycle_happens_only_for_the_sole_owner` | with up to three pieces, made by cloning or splitting, the free list stays empty until the last piece is dropped |
| `checksum_flags_clear_on_any_byte_change` | over any three steps of verifying, editing, editing the header and moving the packet, a flag is set only if the stack set it and no later edit could have changed what it covers |

None of these has been run yet. To run one:

```sh
cargo kani -p fictionet-buf --harness a_pooled_backing_is_charged_to_one_budget_at_every_instant
cargo kani -p fictionet --harness checksum_flags_clear_on_any_byte_change
```

Run Cargo under `systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0`
with the worktree's `CARGO_TARGET_DIR`.

The randomized model test in `buf/src/tests.rs` covers what these bounded
sequences cannot: hundreds of calls over two budgets and a pool, checking
after each that every budget holds exactly one charge per backing it pays
for, that every view shows the bytes the model says, and that a refused
take changes nothing.
