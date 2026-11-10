import Ip

/-! `#print axioms` for every headline theorem. Each line must list only
`propext`, `Quot.sound` and `Classical.choice`, or a subset. -/

-- Checksum, header and UDP

-- Reassembly
#print axioms Ip.Reassembly.complete
#print axioms Ip.Reassembly.finish_ipv4
#print axioms Ip.Reassembly.finish_ipv6
#print axioms Ip.Reassembly.arrived6_names_fragment
#print axioms Ip.Reassembly.reassemble_sound
#print axioms Ip.Reassembly.hist_reassemble
#print axioms Ip.Reassembly.complete_iff_noHoles
#print axioms Ip.Reassembly.overlap_kills
#print axioms Ip.Reassembly.copy_ignored
#print axioms Ip.Reassembly.length_disagreement_kills
#print axioms Ip.Reassembly.dead_stays_dead
#print axioms Ip.Reassembly.too_long_discarded
#print axioms Ip.Reassembly.finish_none_iff
#print axioms Ip.Reassembly.reassemble_inv
#print axioms Ip.Reassembly.reassemble_check
#print axioms Ip.Reassembly.first_fragment_deadline
#print axioms Ip.Reassembly.arrived_timeout
#print axioms Ip.Reassembly.late_completes_nothing
#print axioms Ip.Reassembly.atomic_alone
#print axioms Ip.Reassembly.bad_discarded
#print axioms Ip.Reassembly.arrived_header
#print axioms Ip.Reassembly.expire_out
#print axioms Ip.Reassembly.reassemble_out
#print axioms Ip.Reassembly.firstPacket_none
#print axioms Ip.Reassembly.firstPacket_dead
#print axioms Ip.Reassembly.firstPacket_from
#print axioms Ip.Reassembly.expire_from
#print axioms Ip.Reassembly.arrived4_rebuild
#print axioms Ip.Reassembly.arrived6_rebuild

-- IPv6 extension headers and ICMP
#print axioms Ip.Ext6.chain6_check_eq_rfc
#print axioms Ip.Ext6.optWalk_eq_rfc
#print axioms Ip.Ext6.chain6_problem2
#print axioms Ip.Ext6.chain6_pos
#print axioms Ip.Ext6.strip_spec
#print axioms Ip.Icmp.filled_verifies
#print axioms Ip.Icmp.error_message
#print axioms Ip.Icmp.error_checksum
#print axioms Ip.Icmp.error_quote
#print axioms Ip.Icmp.error_v4_allowed
#print axioms Ip.Icmp.error_v4_sent
#print axioms Ip.Icmp.error_v6_allowed
#print axioms Ip.Icmp.error_v6_sent
#print axioms Ip.Icmp.parameter_problem_option
#print axioms Ip.Icmp.echo_reply_copies
