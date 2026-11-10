import Hpack

/-! The axioms each headline theorem rests on. `cargo xtask hpack-verify lean`
fails if any line names an axiom other than `propext`, `Quot.sound` and
`Classical.choice`. -/

-- Integers (section 5.1)
#print axioms Hpack.decode_encode
#print axioms Hpack.encode_length
#print axioms Hpack.encode_bytes
#print axioms Hpack.decode_ignores_flags
#print axioms Hpack.decode_complete
#print axioms Hpack.decode_truncated

-- Huffman (section 5.2, Appendix B)
#print axioms Hpack.paths_ok
#print axioms Hpack.leaves_ok
#print axioms Hpack.ones_ok
#print axioms Hpack.decode_encode_huffman
#print axioms Hpack.decode_exact
#print axioms Hpack.padding_too_long
#print axioms Hpack.padding_not_ones
#print axioms Hpack.eos_refused
#print axioms Hpack.too_long

-- The dynamic table (sections 2.3, 4.1 to 4.4)
#print axioms Hpack.insert_is_rfc
#print axioms Hpack.insert_exact
#print axioms Hpack.insert_first
#print axioms Hpack.insert_oversized
#print axioms Hpack.evict_fit
#print axioms Hpack.fit_longest
#print axioms Hpack.lookup_some
#print axioms Hpack.lookup_insert

-- Blocks and size updates (sections 4.2, 6, 6.3)
#print axioms Hpack.parse_write
#print axioms Hpack.parse_updates_first
#print axioms Hpack.decode_reduced
#print axioms Hpack.acks_then_block
#print axioms Hpack.decode_updates
#print axioms Hpack.decode_state

-- Encoder and decoder in step
#print axioms Hpack.inStep_new
#print axioms Hpack.inStep_settings
#print axioms Hpack.inStep_capacity
#print axioms Hpack.block_round_trip
#print axioms Hpack.rustPolicy_wf
