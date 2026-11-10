import Ip

/-! `#print axioms` for every headline theorem. Each line must list only
`propext`, `Quot.sound` and `Classical.choice`, or a subset. -/

-- Checksum, header and UDP
#print axioms Ip.Checksum.foldNat_eq_rep
#print axioms Ip.Checksum.onesSum_eq_rep
#print axioms Ip.Checksum.rust_checksum
#print axioms Ip.Checksum.rust_sum_sum
#print axioms Ip.Checksum.rust_split
#print axioms Ip.Checksum.rust_pseudo4
#print axioms Ip.Checksum.rust_pseudo6
#print axioms Ip.Checksum.verifies
#print axioms Ip.Checksum.fold_zero
#print axioms Ip.Checksum.fold_eq_ffff_iff
#print axioms Ip.Checksum.fold_eq_zero_iff
#print axioms Ip.Checksum.checksum_of_zeros
#print axioms Ip.Checksum.zero_fields_agree
#print axioms Ip.Checksum.one_octet_detected
#print axioms Ip.Checksum.one_bit_detected
#print axioms Ip.Header.v4_some_iff
#print axioms Ip.Header.v4_payload
#print axioms Ip.Header.check_some_iff
#print axioms Ip.Header.whole_some_iff
#print axioms Ip.Header.v4_ignores
#print axioms Ip.Header.v4_ignores_flag_bits
#print axioms Ip.Header.dstPort_none
#print axioms Ip.Header.build_checks
#print axioms Ip.Header.hop_v4_expired
#print axioms Ip.Header.hop_v6
#print axioms Ip.Header.hop_v4
#print axioms Ip.Header.hop_keeps_checksum
#print axioms Ip.Header.hop_is_recompute
#print axioms Ip.Udp.rust_checksumOk
#print axioms Ip.Udp.parse_some_iff
#print axioms Ip.Udp.zero_field_v4
#print axioms Ip.Udp.zero_field_v6
#print axioms Ip.Udp.encode_parses
#print axioms Ip.Udp.encode_verifies
#print axioms Ip.Udp.one_octet_fails
#print axioms Ip.Udp.encodedLen_ok
#print axioms Ip.Udp.encodedLen_mixed

-- Reassembly

-- IPv6 extension headers and ICMP
