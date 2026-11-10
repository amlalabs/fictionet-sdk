# RFC 9293 segment arrival in Lean 4

Lean core, with toolchain `leanprover/lean4:v4.35.0`. It uses no Mathlib,
no `sorry`, no native decision and no axioms beyond Lean's own. Run
`cargo xtask tcp-rfc-verify lean` for the build and the axioms audit, and
`cargo xtask tcp-rfc-verify diff` for the differential test on seeds 1 to
8. Set `LAKE` when `lake` is not on `PATH`.

| Module | Contents |
|---|---|
| `TcpRfc/Seq.lean` | Sequence numbers modulo 2^32 (RFC 9293 3.4). Every chain such as `a < b =< c` is read as an offset from its left end. It also has the four-case acceptability table, and smoltcp's signed `SeqNumber` order. |
| `TcpRfc/Arrive.lean` | `arrive : Departures → Tcb → Segment → Tcb × Reply`, section 3.10.7, with RFC 5961 3.2, 4.2 and 5.2/7. |
| `TcpRfc/Theorems.lean` | The theorems about `arrive` listed below. |
| `TcpRfc/Axioms.lean` | `#print axioms` for each of the 41 headline theorems. |
| `Gen.lean` | Vectors for `smoltcp/src/socket/tcp/rfc_vectors.rs`. |

## The model

`arrive` covers CLOSED (3.10.7.1), LISTEN (3.10.7.2), SYN-SENT
(3.10.7.3), SYN-RECEIVED and the seven synchronized states (3.10.7.4).
The 3.10.7.4 checks run in the RFC's order: acceptability, RST, SYN, ACK,
text, FIN.

A segment is SEG.SEQ, an optional ACK, one control (none, SYN, FIN or
RST) and a text length. smoltcp's parser drops SYN with FIN and gives RST
priority over the others. PSH changes nothing.

The record (`Tcb`) holds:
- the state, ISS and IRS;
- SND.UNA, SND.NXT, RCV.NXT and RCV.WND;
- whether our SYN and our FIN have gone out;
- whether the peer's FIN has arrived;
- whether the connection opened passively.

A reply is one of these:
- nothing;
- `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`;
- the same segment as a challenge ACK, which RFC 5961 section 7 lets a rate
  limit hold back;
- `<SEQ=SEG.ACK><CTL=RST>`;
- `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`;
- a SYN-ACK.

Where the RFC leaves a choice, the model makes one. These choices match
`../tla/Rfc9293.tla`.

- **When an ACK goes out.** The RFC lets an owed ACK go out at once or
  later (3.8.6.3). The model sends it at once in three cases: when RCV.NXT
  moves; when text arrives past a hole (RFC 5681 4.2, MAY-13); and for
  text at the left edge of a closed window. A segment that moves nothing
  gets no reply.
- **Text past a hole.** It may be held (SHLD-31) or dropped. The record
  keeps no reassembly queue, so either way the step only shows that
  RCV.NXT stays. The segment's ACK is still processed.
- **The 2^31 point.** An ACK exactly 2^31 past SND.NXT, which RFC 1982
  leaves unordered, is counted as ahead. It is challenged and never taken
  as new.
- **SYN in a synchronized state.** It is challenged wherever it lies (RFC
  5961 4.2, "irrespective of the sequence number"). In SYN-RECEIVED the
  first check still comes first.
- **Closed-window text.** Text at RCV.NXT of a closed window is
  unacceptable. The first check answers it with an ACK, and its ACK field
  is still processed ("special allowance should be made to accept valid
  ACKs"). The answer goes out even when that ACK closes the connection
  from LAST-ACK, and it carries the numbers from before the step.
- **RST.** A RST is judged by SEG.SEQ alone (RFC 5961 3.2). In SYN-SENT
  it is not compared with RCV.NXT, which is not known yet.
- **RCV.WND.** RCV.WND follows the buffer: taken text shrinks it and a FIN
  does not.
- **After the peer's FIN.** Text is ignored. A further FIN changes nothing
  (eighth check: "remain in" the state), but its ACK counts.

## Departures

Each field of `Departures` is a deliberate departure of the code. With all
fields false, `arrive` is the RFC. `Departures.smoltcp` sets every field
but `repeatSynAck` (`Settings::repeat_syn_ack`, off by default).

| Flag | The code does | The RFC clause it leaves | Where |
|---|---|---|---|
| `repeatSynAck` | In SYN-RECEIVED, drops a repeated SYN so the SYN-ACK goes out again | 3.10.7.4 fourth: a passive open returns to LISTEN | `process`, `repeat_syn_ack` |
| `ackBeforeSeqInSynReceived` | In SYN-RECEIVED, resets a bad ACK before the sequence check (Linux `tcp_check_req`) | 3.10.7.4: sequence first, ACK fifth | `process`, `(SynReceived, _, Some(ack))` arm |
| `challengeSynInSynReceived` | Answers a SYN in SYN-RECEIVED with a challenge ACK | 3.10.7.4 fourth: back to LISTEN | `process`, the SYN test before the first match |
| `noAckDroppedFirst` | Drops a non-RST segment without ACK before the sequence check (Linux `tcp_rcv_state_process`) | 3.10.7.4 first: an unacceptable segment gets an ACK | `process`, `(_, _, None) => return None` |
| `ackCheckedBeforeSeq` | In a synchronized state, challenges an ACK ahead of SND.NXT before the sequence check | 3.10.7.4: sequence first, so the reply would be a plain ACK | `process`, last arm of the first match |
| `rateLimitEmptyOutOfWindow` | Answers an unacceptable segment with no text and no FIN with a challenge ACK the rate limit may hold back (Linux `tcp_oow_rate_limited`) | 3.10.7.4 first: a plain ACK | `process`, `segment_len() > 0` test |
| `emptyAckAtRightEdge` | Accepts a segment with no text and no control at exactly RCV.NXT+RCV.WND, when RCV.WND > 0 | Table 6: `SEG.SEQ < RCV.NXT+RCV.WND` | `segment_in_window` |
| `finAtRightEdge` | Takes a FIN that comes in order exactly at RCV.NXT+RCV.WND: a bare FIN at RCV.NXT of a closed window (`test_zero_window_fin`, as Linux does), or a FIN right after text that fills the window | 3.10.7.4: trim "any portions that lie outside the window (including SYN and FIN)" | `process`, FIN test (`segment_end` leaves the FIN out); `segment_in_window` |
| `textOnSynDropped` | Does not take text on a SYN-ACK | 3.10.7.3: such text should be processed (a SHOULD) | `process` gives LISTEN and SYN-SENT an empty payload |

In LISTEN, and on a SYN in SYN-SENT without an ACK, the RFC queues a SYN's
text for later. A single step cannot tell that apart from dropping it, so
`textOnSynDropped` is about SYN-ACKs alone.

## Theorems

All theorems hold for every set of departures, every 32-bit value and
every segment, unless a hypothesis says otherwise.

Sequence numbers (`Seq.lean`):
- `acceptable_eq_table`: the offset test equals the RFC's four-case table,
  for every window below 2^32 (3.4, 3.10.7.4 table 6).
- `acceptable_lift`: the 32-bit test on reduced numbers matches the table
  on unbounded integers. This holds across wraparound for any RCV.NXT and
  SEG.SEQ less than 2^31 apart.
- `half_unordered`, `ordered_otherwise`: `SeqNumber` leaves exactly the
  pairs 2^31 apart unordered.
- `signed_window_iff`: smoltcp's `start <= seq && seq < end` equals the
  offset test for every window below 2^31.
- `signed_window_fails_at_half`: at a window of exactly 2^31 the signed
  form rejects SEG.SEQ = RCV.NXT. smoltcp's window is at most 2^30.
- `signed_ahead_iff`: smoltcp's `!(ack <= SND.MAX)` is exactly the
  model's `ahead`, the 2^31 point included.
- `new_not_ahead`, `signed_advance_iff`: while less than half the space is
  in flight, smoltcp's `ack <= SND.MAX && !(ack < SND.UNA)` is the RFC's
  `SND.UNA < SEG.ACK =< SND.NXT`, or an ACK that repeats SND.UNA.

Arrival (`Theorems.lean`):
- `rst_off_rcvNxt_keeps_connection`: in SYN-RECEIVED and the synchronized
  states, a RST not exactly at RCV.NXT leaves the record unchanged. It is
  dropped or challenged (RFC 5961 3.2).
- `rst_or_syn_keeps_numbers`: a RST or SYN there never moves RCV.NXT,
  SND.UNA or SND.NXT.
- `sndNxt_kept`: arrival never moves SND.NXT, outside LISTEN.
- `sndUna_offset_rule`: SND.UNA moves only to SEG.ACK, and only when
  `SND.UNA < SEG.ACK =< SND.NXT` (3.10.7.3, 3.10.7.4 fifth).
- `sndUna_never_passes_sndNxt`: the offset from SND.UNA to SND.NXT only
  shrinks.
- `rcvNxt_moves_by_text`: RCV.NXT moves by n + f. Here n is octets of this
  segment's text from RCV.NXT on, taken only when the segment reaches
  RCV.NXT and the peer's FIN has not arrived, and never more than RCV.WND.
  f is one for a FIN right after the segment's last octet. Without
  `finAtRightEdge` RCV.NXT stays in the window; with it, it moves one past
  the window, for the FIN.
- `replies_ack_rcvNxt`: every ACK and challenge ACK carries the record's
  SND.NXT and RCV.NXT after the step, and a SYN-ACK carries the ISS and
  RCV.NXT. With the theorem above, no reply acknowledges past what was
  taken.
- `fin_only_in_order`: the peer's FIN is taken only when the segment
  reaches RCV.NXT, and RCV.NXT lands at SEG.SEQ+SEG.LEN.
- `nothing_taken_after_fin`: after the peer's FIN, RCV.NXT stays.
- `right_edge_kept`: RCV.NXT+RCV.WND never moves left (3.10.7.4 seventh).
- `rfc_unacceptable_acked`: with the RFC's flags, an unacceptable segment
  with no RST or SYN gets the ACK and changes nothing.
- `syn_sent_bad_ack_reset`: in SYN-SENT a bad ACK draws
  `<SEQ=SEG.ACK><CTL=RST>` for any control but RST (the fix in
  `5a652ed66`).
- `half_space_ack_not_taken`: an ACK 2^31 past SND.UNA never changes a
  synchronized record (the fix in `8b882f969`).
- `time_wait_fin_again_acked`: in TIME-WAIT the peer's FIN sent again is
  ACKed and changes nothing, under every set of departures (the fix in
  `8b882f969`).
- `local_<flag>`, one per departure: outside the flag's case (`…Case` in
  `Arrive.lean`), `arrive` gives the same result with the flag on as off,
  whatever the other flags are.
- `used_<flag>`, one per departure: a concrete record and segment in the
  flag's case where turning that flag on alone changes the RFC's result.
  These are checked by `decide`.

## How the vectors tie the model to the code

`gen <dir> <seed>` writes `arrive.txt`, one line per vector: the record,
the segment, and the record and reply that `arrive Departures.smoltcp`
gives.

The boundary set is the same for every seed. It takes six (SND.UNA,
RCV.NXT) pairs at 0, 2^31 and 2^32 - 1 and their neighbours, and covers:
- every state, 0 or 3 octets in flight, RCV.WND 0, 1 and 4;
- passive and active SYN-RECEIVED;
- text lengths 0, 1, 2, RCV.WND and RCV.WND + 1;
- twelve SEG.SEQ values: the window edges ±1, ±2^31, and where a FIN lands
  at RCV.NXT and at the right edge;
- ten ACKs: none, SND.UNA-1, SND.UNA, SND.UNA+1, SND.NXT, SND.NXT+1,
  SND.UNA+2^31-1, SND.UNA+2^31, SND.UNA+2^31+1 and SND.NXT+2^31;
- every control.

Each seed then adds 50,000 random cases.

`rfc9293_arrival_vectors`, in smoltcp's TCP test module, replays the
vectors:
- It builds a socket in each record, as the `socket_*` helpers do. The
  socket has sent everything it holds and owes nothing.
- It feeds the segment to `process`. In LISTEN and CLOSED it does what
  `process_tcp` does instead: a RST for anything but a RST.
- It takes the reply from `process`, or else from one `dispatch` at the
  same instant.
- It compares the reply and the record exactly. In CLOSED and LISTEN only
  the state is compared, because the record is deleted.

Each vector runs twice: once with the challenge-ACK rate limit open, where
a challenge must go out as an ACK, and once with it closed, where it must
not and nothing else may change. Disagreements are grouped by state,
control, ACK and what differs, and every one fails the test.

Turning off `emptyAckAtRightEdge` and `finAtRightEdge` in
`Departures.smoltcp` makes thousands of vectors disagree, so the replay
notices a wrong departure.

## Last run (2026-11-10, tree at `c449d4333`)

- `lean`: the build passes and all 41 headline theorems rest on `propext`,
  `Quot.sound` and `Classical.choice` at most. `Seq.lean` and
  `Theorems.lean` hold 61 theorems in all.
- `diff`: each of seeds 1 to 8 has 746,960 vectors (696,960 boundary and
  50,000 random), run twice each, with 0 disagreements.
- Over seed 1's vectors, the replies are 232,863 none, 71,712 ACK,
  260,148 challenge, 173,951 RST, 4,966 RST-ACK and 3,320 SYN-ACK. Every
  transition of 3.3.2 that arrival can make appears.

## What the model found

Writing the model found three departures, fixed in `8b882f969` and
`5a652ed66` before this replay. While the replay was being built,
`d33b8023e` fixed two more behaviours that the RFC does not allow:
- smoltcp dropped a second FIN together with the ACK it carried;
- it left closed-window text unanswered in TIME-WAIT.

The model follows the RFC on both, and the replay agrees with the fixed
code on every vector. The replay found no disagreement that is not
listed as a departure.

## What `arrive` leaves out

- Send and congestion windows, SND.WND/WL1/WL2, retransmission and its
  timers, keep-alive, delayed-ACK timing, Nagle, MSS and every option:
  window scale, timestamps and PAWS, SACK, MPTCP.
- The reassembly queue. Text held past a hole is not tracked, so a step
  cannot show whether it is later used. smoltcp keeps such text in its
  assembler but drops a FIN past a hole, so the peer has to send that FIN
  again.
- Urgent data, security and compartment, and ICMP.
- The socket's handshake ISS. In LISTEN it is the test interface's
  `LOCAL_SEQ`, because `initial_seq` is private to the interface. The
  other states start at every boundary value.
- Sockets with unsent data, a FIN not yet sent, or a SYN not yet sent. The
  replay builds sockets that have sent everything they hold, so the
  `dispatch` after `process` shows only the reply.
- RCV.WND and in-flight data are small (up to 63 and 8 octets). The window
  theorems in `Seq.lean` cover every 32-bit width.
- RFC 5961 5.2's lower bound, `SND.UNA - MAX.SND.WND`. smoltcp ignores old
  ACKs, as RFC 9293 allows without RFC 5961 section 5, and the model does
  the same.
