import Ip

/-! `#print axioms` for every headline theorem. Each line must list only
`propext`, `Quot.sound` and `Classical.choice`, or a subset. -/

-- Checksum, header and UDP

-- Reassembly

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
